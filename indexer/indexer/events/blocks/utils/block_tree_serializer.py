from __future__ import annotations

import base64
import hashlib
import logging

from indexer.core.database import Action
from indexer.events.blocks.auction import AuctionBidBlock
from indexer.events.blocks.basic_blocks import (
    CallContractBlock,
    ContractDeployBlock,
    TonTransferBlock,
)
from indexer.events.blocks.core import Block
from indexer.events.blocks.dns import (
    DnsChangeRecordBlock,
    DnsDeleteRecordBlock,
    DnsRenewBlock,
)
from indexer.events.blocks.elections import (
    ElectionDepositStakeBlock,
    ElectionRecoverStakeBlock,
)
from indexer.events.blocks.jettons import (
    JettonBurnBlock,
    JettonMintBlock,
    JettonTransferBlock,
)
from indexer.events.blocks.jvault import (
    JVaultClaimBlock,
    JVaultStakeBlock,
    JVaultUnstakeBlock,
)
from indexer.events.blocks.liquidity import (
    DedustDepositLiquidityBlock,
    DedustDepositLiquidityPartialBlock,
    DexDepositLiquidityBlock,
    DexWithdrawLiquidityBlock,
)
from indexer.events.blocks.multisig import (
    MultisigApproveBlock,
    MultisigCreateOrderBlock,
)
from indexer.events.blocks.nft import NftDiscoveryBlock, NftMintBlock, NftTransferBlock
from indexer.events.blocks.staking import (
    NominatorPoolDepositBlock,
    NominatorPoolWithdrawRequestBlock,
    TONStakersDepositBlock,
    TONStakersWithdrawBlock,
    TONStakersWithdrawRequestBlock,
)
from indexer.events.blocks.subscriptions import SubscribeBlock, UnsubscribeBlock
from indexer.events.blocks.swaps import JettonSwapBlock
from indexer.events.blocks.utils import AccountId, Asset
from indexer.events.blocks.vesting import (
    VestingAddWhiteListBlock,
    VestingSendMessageBlock,
)

logger = logging.getLogger(__name__)


def _addr(addr: AccountId | Asset | None) -> str | None:
    if addr is None:
        return None
    if isinstance(addr, Asset):
        return addr.jetton_address.as_str() if addr.jetton_address is not None else None
    else:
        return addr.as_str()


def _calc_action_id(block: Block) -> str:
    root_event_node = min(block.event_nodes, key=lambda n: n.get_lt())
    key = ""
    if root_event_node.message is not None:
        key = root_event_node.message.msg_hash
    else:
        key = root_event_node.get_tx_hash() or ""
    key += block.btype
    h = hashlib.sha256(key.encode())
    return base64.b64encode(h.digest()).decode()


def _base_block_to_action(block: Block, trace_id: str) -> Action:
    action_id = _calc_action_id(block)
    tx_hashes = list(set(n.get_tx_hash() for n in block.event_nodes))
    accounts = []
    for n in block.event_nodes:
        if n.is_tick_tock:
            accounts.append(n.tick_tock_tx.account)
        else:
            accounts.append(n.message.transaction.account)

    action = Action(
        trace_id=trace_id,
        type=block.btype,
        action_id=action_id,
        tx_hashes=tx_hashes,
        start_lt=block.min_lt,
        end_lt=block.max_lt,
        start_utime=block.min_utime,
        end_utime=block.max_utime,
        success=not block.failed,
    )
    action.accounts = accounts
    return action


def _convert_peer_swap(peer_swap: dict) -> dict:
    in_obj = peer_swap["in"]
    out_obj = peer_swap["out"]
    return {
        "amount_in": in_obj["amount"].value,
        "asset_in": (
            in_obj["asset"].jetton_address.as_str()
            if in_obj["asset"].jetton_address is not None
            else None
        ),
        "amount_out": out_obj["amount"].value,
        "asset_out": (
            out_obj["asset"].jetton_address.as_str()
            if out_obj["asset"].jetton_address is not None
            else None
        ),
    }


def _fill_call_contract_action(
    block: CallContractBlock | ContractDeployBlock, action: Action
):
    action.opcode = block.opcode
    action.value = block.data["value"].value
    action.source = (
        block.data["source"].as_str() if block.data["source"] is not None else None
    )
    action.destination = (
        block.data["destination"].as_str()
        if block.data["destination"] is not None
        else None
    )


def _fill_ton_transfer_action(block: TonTransferBlock, action: Action):
    action.value = block.value
    action.source = block.data["source"].as_str()
    if block.data["destination"] is None:
        print("Something very wrong", block.event_nodes[0].message.trace_id)
    action.destination = block.data["destination"].as_str()
    content = (
        block.data["comment"].replace("\u0000", "")
        if block.data["comment"] is not None
        else None
    )
    action.ton_transfer_data = {
        "content": content,
        "encrypted": block.data["encrypted"],
    }


def _fill_jetton_transfer_action(block: JettonTransferBlock, action: Action):
    action.source = block.data["sender"].as_str()
    action.source_secondary = block.data["sender_wallet"].as_str()
    action.destination = block.data["receiver"].as_str()
    action.destination_secondary = (
        block.data["receiver_wallet"].as_str()
        if "receiver_wallet" in block.data
        else None
    )
    action.amount = block.data["amount"].value
    asset = block.data["asset"]
    if asset is None or asset.is_ton:
        action.asset = None
    else:
        action.asset = asset.jetton_address.as_str()
    comment = None
    if block.data["comment"] is not None:
        if block.data["encrypted_comment"]:
            comment = base64.b64encode(block.data["comment"]).decode("utf-8")
        else:
            comment = block.data["comment"].decode("utf-8").replace("\u0000", "")
    action.jetton_transfer_data = {
        "query_id": block.data["query_id"],
        "response_destination": (
            block.data["response_address"].as_str()
            if block.data["response_address"] is not None
            else None
        ),
        "forward_amount": block.data["forward_amount"].value,
        "custom_payload": block.data["custom_payload"],
        "forward_payload": block.data["forward_payload"],
        "comment": comment,
        "is_encrypted_comment": block.data["encrypted_comment"],
    }


def _fill_nft_transfer_action(block: NftTransferBlock, action: Action):
    if "prev_owner" in block.data and block.data["prev_owner"] is not None:
        action.source = block.data["prev_owner"].as_str()
    action.destination = block.data["new_owner"].as_str()
    action.asset_secondary = block.data["nft"]["address"].as_str()
    if block.data["nft"]["collection"] is not None:
        action.asset = block.data["nft"]["collection"]["address"].as_str()
    action.nft_transfer_data = {
        "query_id": block.data["query_id"],
        "is_purchase": block.data["is_purchase"],
        "price": (
            block.data["price"].value
            if "price" in block.data and block.data["is_purchase"]
            else None
        ),
        "nft_item_index": block.data["nft"]["index"],
        "forward_amount": (
            block.data["forward_amount"].value
            if block.data["forward_amount"] is not None
            else None
        ),
        "custom_payload": block.data["custom_payload"],
        "forward_payload": block.data["forward_payload"],
        "response_destination": (
            block.data["response_destination"].as_str()
            if block.data["response_destination"]
            else None
        ),
    }


def _fill_nft_discovery_action(block: NftDiscoveryBlock, action: Action):
    action.source = block.data.sender.as_str()
    action.destination = block.data.nft.as_str()
    action.nft_discovery_data = {
        "query_id": block.data.query_id,
        "collection_address": block.data.result_collection.as_str(),
        "nft_item_index": block.data.result_index,
    }


def _fill_nft_mint_action(block: NftMintBlock, action: Action):
    if block.data["source"]:
        action.source = block.data["source"].as_str()
    action.destination = block.data["address"].as_str()
    action.asset_secondary = action.destination
    action.opcode = block.data["opcode"]
    if block.data["collection"]:
        action.asset = block.data["collection"].as_str()
    action.nft_mint_data = {
        "nft_item_index": block.data["index"],
    }


def _fill_jetton_swap_action(block: JettonSwapBlock, action: Action):
    dex_incoming_transfer = {
        "amount": block.data["dex_incoming_transfer"]["amount"].value,
        "source": _addr(block.data["dex_incoming_transfer"]["source"]),
        "source_jetton_wallet": _addr(
            block.data["dex_incoming_transfer"]["source_jetton_wallet"]
        ),
        "destination": _addr(block.data["dex_incoming_transfer"]["destination"]),
        "destination_jetton_wallet": _addr(
            block.data["dex_incoming_transfer"]["destination_jetton_wallet"]
        ),
        "asset": _addr(block.data["dex_incoming_transfer"]["asset"]),
    }
    dex_outgoing_transfer = {
        "amount": block.data["dex_outgoing_transfer"]["amount"].value,
        "source": _addr(block.data["dex_outgoing_transfer"]["source"]),
        "source_jetton_wallet": _addr(
            block.data["dex_outgoing_transfer"]["source_jetton_wallet"]
        ),
        "destination": _addr(block.data["dex_outgoing_transfer"]["destination"]),
        "destination_jetton_wallet": _addr(
            block.data["dex_outgoing_transfer"]["destination_jetton_wallet"]
        ),
        "asset": _addr(block.data["dex_outgoing_transfer"]["asset"]),
    }
    action.asset = dex_incoming_transfer["asset"]
    action.asset2 = dex_outgoing_transfer["asset"]
    if block.data["dex"] == "stonfi_v2":
        action.asset = _addr(block.data["source_asset"])
        action.asset2 = _addr(block.data["destination_asset"])
    action.source = dex_incoming_transfer["source"]
    action.source_secondary = dex_incoming_transfer["source_jetton_wallet"]
    action.destination = dex_outgoing_transfer["destination"]
    action.destination_secondary = dex_outgoing_transfer["destination_jetton_wallet"]
    if (
        "destination_wallet" in block.data
        and block.data["destination_wallet"] is not None
    ):
        action.destination_secondary = _addr(block.data["destination_wallet"])
    if (
        "destination_asset" in block.data
        and block.data["destination_asset"] is not None
    ):
        action.asset2 = _addr(block.data["destination_asset"])

    action.jetton_swap_data = {
        "dex": block.data["dex"],
        "sender": _addr(block.data["sender"]),
        "dex_incoming_transfer": dex_incoming_transfer,
        "dex_outgoing_transfer": dex_outgoing_transfer,
    }


def _fill_dex_deposit_liquidity(block: Block, action: Action):
    action.source = _addr(block.data["sender"])
    action.destination = _addr(block.data["pool"])
    action.dex_deposit_liquidity_data = {
        "dex": block.data["dex"],
        "amount1": (
            block.data["amount_1"].value if block.data["amount_1"] is not None else None
        ),
        "amount2": (
            block.data["amount_2"].value if block.data["amount_2"] is not None else None
        ),
        "asset1": _addr(block.data["asset_1"]),
        "asset2": _addr(block.data["asset_2"]),
        "user_jetton_wallet_1": _addr(block.data["sender_wallet_1"]),
        "user_jetton_wallet_2": _addr(block.data["sender_wallet_2"]),
        "lp_tokens_minted": (
            block.data["lp_tokens_minted"].value
            if block.data["lp_tokens_minted"] is not None
            else None
        ),
    }


def _fill_dex_withdraw_liquidity(block: Block, action: Action):
    action.source = _addr(block.data["sender"])
    action.source_secondary = _addr(block.data["sender_wallet"])
    action.destination = _addr(block.data["pool"])
    action.asset = _addr(block.data["asset"])
    action.dex_withdraw_liquidity_data = {
        "dex": block.data["dex"],
        "amount_1": (
            block.data["amount1_out"].value
            if block.data["amount1_out"] is not None
            else None
        ),
        "amount_2": (
            block.data["amount2_out"].value
            if block.data["amount2_out"] is not None
            else None
        ),
        "asset_out_1": _addr(block.data["asset1_out"]),
        "asset_out_2": _addr(block.data["asset2_out"]),
        "user_jetton_wallet_1": _addr(block.data["wallet1"]),
        "user_jetton_wallet_2": _addr(block.data["wallet2"]),
        "dex_jetton_wallet_1": _addr(block.data["dex_jetton_wallet_1"]),
        "dex_wallet_1": _addr(block.data["dex_wallet_1"]),
        "dex_wallet_2": _addr(block.data["dex_wallet_2"]),
        "dex_jetton_wallet_2": _addr(block.data["dex_jetton_wallet_2"]),
        "is_refund": block.data["is_refund"],
        "lp_tokens_burnt": (
            block.data["lp_tokens_burnt"].value
            if block.data["lp_tokens_burnt"] is not None
            else None
        ),
    }


def _fill_jvault_stake(block: JVaultStakeBlock, action: Action):
    action.source = _addr(block.data.sender)
    action.source_secondary = _addr(block.data.stake_wallet)
    action.destination = _addr(block.data.staking_pool)
    action.amount = block.data.staked_amount
    action.jvault_stake_data = {
        "period": block.data.period,
        "minted_stake_jettons": block.data.minted_stake_jettons,
    }


def _fill_jvault_unstake(block: JVaultUnstakeBlock, action: Action):
    action.source = _addr(block.data.sender)
    action.source_secondary = _addr(block.data.stake_wallet)
    action.destination = _addr(block.data.staking_pool)
    action.amount = block.data.unstaked_amount


def _fill_jvault_claim(block: JVaultClaimBlock, action: Action):
    action.source = _addr(block.data.sender)
    action.source_secondary = _addr(block.data.stake_wallet)
    action.destination = _addr(block.data.staking_pool)
    action.jvault_claim_data = {
        "claimed_jettons": list(map(_addr, block.data.claimed_jettons)),
        "claimed_amounts": block.data.claimed_amounts,
    }


def _fill_multisig_create_order(block: MultisigCreateOrderBlock, action: Action):
    action.source = _addr(block.data.created_by)
    action.destination = _addr(block.data.multisig)
    action.destination_secondary = _addr(block.data.order_contract_address)
    action.multisig_create_order_data = {
        "query_id": block.data.query_id,
        "order_seqno": block.data.order_seqno,
        "is_created_by_signer": block.data.is_created_by_signer,
        "is_signed_by_creator": block.data.creator_approved,
        "creator_index": block.data.creator_index,
        "expiration_date": block.data.expiration_date,
        "order_boc": block.data.order_boc_str,
    }


def _fill_multisig_approve(block: MultisigApproveBlock, action: Action):
    action.source = _addr(block.data.signer)
    action.destination = _addr(block.data.order)
    action.success = block.data.success
    action.multisig_approve_data = {
        "signer_index": block.data.signer_index,
        "exit_code": block.data.exit_code,
    }


def _fill_vesting_send_message(block: VestingSendMessageBlock, action: Action):
    action.source = _addr(block.data.sender)
    action.destination = _addr(block.data.vesting)
    action.destination_secondary = _addr(
        block.data.message_destination
    )  # where the msg was sent to
    action.amount = block.data.message_value.value  # the value of the msg
    action.vesting_send_message_data = {
        "query_id": block.data.query_id,
        "message_boc": block.data.message_boc_str,
    }


def _fill_vesting_add_whitelist(block: VestingAddWhiteListBlock, action: Action):
    action.source = _addr(block.data.adder)
    action.destination = _addr(block.data.vesting)
    action.vesting_add_whitelist_data = {
        "query_id": block.data.query_id,
        "accounts_added": list(map(_addr, block.data.accounts_added)),
    }


def _fill_jetton_burn_action(block: JettonBurnBlock, action: Action):
    action.source = block.data["owner"].as_str()
    action.source_secondary = block.data["jetton_wallet"].as_str()
    action.asset = block.data["asset"].jetton_address.as_str()
    action.amount = block.data["amount"].value


def _fill_change_dns_record_action(block: DnsChangeRecordBlock, action: Action):
    action.source = (
        block.data["source"].as_str() if block.data["source"] is not None else None
    )
    action.destination = block.data["destination"].as_str()
    dns_record_data = block.data["value"]
    data = {
        "value_schema": dns_record_data["schema"],
        "flags": None,
        "address": None,
        "key": block.data["key"].hex(),
    }
    if data["value_schema"] in ("DNSNextResolver", "DNSSmcAddress"):
        data["address"] = dns_record_data["address"].as_str()
    elif data["value_schema"] == "DNSAdnlAddress":
        data["address"] = dns_record_data["address"].hex()
        data["flags"] = dns_record_data["flags"]
    if data["value_schema"] == "DNSSmcAddress":
        data["flags"] = dns_record_data["flags"]
    if data["value_schema"] == "DNSText":
        data["dns_text"] = dns_record_data["dns_text"]
    action.change_dns_record_data = data


def _fill_delete_dns_record_action(block: DnsDeleteRecordBlock, action: Action):
    action.source = (
        block.data["source"].as_str() if block.data["source"] is not None else None
    )
    action.destination = block.data["destination"].as_str()
    data = {
        "value_schema": None,
        "flags": None,
        "address": None,
        "key": block.data["key"].hex(),
    }
    action.change_dns_record_data = data


def _fill_tonstakers_deposit_action(block: TONStakersDepositBlock, action: Action):
    action.type = "stake_deposit"
    action.source = _addr(block.data.source)
    action.destination = _addr(block.data.pool)
    action.amount = block.data.value.value
    action.staking_data = {
        "provider": "tonstakers",
    }


def _fill_dns_renew_action(block: DnsRenewBlock, action: Action):
    action.source = _addr(block.data["source"])
    action.destination = _addr(block.data["destination"])


def _fill_tonstakers_withdraw_request_action(
    block: TONStakersWithdrawRequestBlock, action: Action
):
    action.source = _addr(block.data.source)
    action.source_secondary = _addr(block.data.tsTON_wallet)
    action.destination = _addr(block.data.pool)
    action.amount = block.data.tokens_burnt.value
    action.type = "stake_withdrawal_request"
    action.staking_data = {
        "provider": "tonstakers",
        "ts_nft": _addr(block.data.minted_nft),
    }


def _fill_tonstakers_withdraw_action(block: TONStakersWithdrawBlock, action: Action):
    action.source = _addr(block.data.stake_holder)
    action.destination = _addr(block.data.pool)
    action.amount = block.data.amount.value
    action.type = "stake_withdrawal"
    action.staking_data = {
        "provider": "tonstakers",
        "ts_nft": _addr(block.data.burnt_nft),
    }


def _fill_subscribe_action(block: SubscribeBlock, action: Action):
    action.source = block.data["subscriber"].as_str()
    action.destination = (
        block.data["beneficiary"].as_str()
        if block.data["beneficiary"] is not None
        else None
    )
    action.destination_secondary = block.data["subscription"].as_str()
    action.amount = block.data["amount"].value


def _fill_unsubscribe_action(block: UnsubscribeBlock, action: Action):
    action.source = block.data["subscriber"].as_str()
    action.destination = (
        block.data["beneficiary"].as_str()
        if block.data["beneficiary"] is not None
        else None
    )
    action.destination_secondary = block.data["subscription"].as_str()


def _fill_election_action(block: Block, action: Action):
    action.source = block.data["stake_holder"].as_str()
    action.amount = block.data["amount"].value if "amount" in block.data else None


def _fill_auction_bid_action(block: Block, action: Action):
    action.source = block.data["bidder"].as_str()
    action.destination = block.data["auction"].as_str()
    action.asset_secondary = block.data["nft_address"].as_str()
    action.asset = _addr(block.data["nft_collection"])
    action.nft_transfer_data = {
        "nft_item_index": block.data["nft_item_index"],
    }
    action.value = block.data["amount"].value


def _fill_dedust_deposit_liquidity_action(
    block: DedustDepositLiquidityBlock, action: Action
):
    action.type = "dex_deposit_liquidity"
    action.source = _addr(block.data["sender"])
    action.destination = _addr(block.data["pool_address"])
    action.destination_secondary = _addr(block.data["deposit_contract"])
    action.dex_deposit_liquidity_data = {
        "dex": block.data["dex"],
        "asset1": _addr(block.data["asset_1"].jetton_address),
        "amount1": block.data["amount_1"].value,
        "asset2": _addr(block.data["asset_2"].jetton_address),
        "amount2": block.data["amount_2"].value,
        "user_jetton_wallet_1": _addr(block.data["user_jetton_wallet_1"]),
        "user_jetton_wallet_2": _addr(block.data["user_jetton_wallet_2"]),
        "lp_tokens_minted": block.data["lp_tokens_minted"].value,
    }


def _fill_dedust_deposit_liquidity_partial_action(
    block: DedustDepositLiquidityPartialBlock, action: Action
):
    action.type = "dex_deposit_liquidity"
    action.source = _addr(block.data["sender"])
    action.destination_secondary = _addr(block.data["deposit_contract"])
    action.dex_deposit_liquidity_data = {
        "dex": block.data["dex"],
        "asset1": _addr(block.data["asset_1"].jetton_address),
        "amount1": block.data["amount_1"].value,
        "asset2": _addr(block.data["asset_2"].jetton_address),
        "amount2": block.data["amount_2"].value,
        "user_jetton_wallet_1": _addr(block.data["user_jetton_wallet_1"]),
        "user_jetton_wallet_2": _addr(block.data["user_jetton_wallet_2"]),
        "lp_tokens_minted": None,
    }


def _fill_jetton_mint_action(block: JettonMintBlock, action: Action):
    action.destination = _addr(block.data["to"])
    action.destination_secondary = _addr(block.data["to_jetton_wallet"])
    action.asset = _addr(block.data["asset"].jetton_address)
    action.amount = (
        block.data["amount"].value if block.data["amount"] is not None else None
    )
    action.value = (
        block.data["ton_amount"].value if block.data["ton_amount"] is not None else None
    )


def _fill_nominator_pool_deposit_action(
    block: NominatorPoolDepositBlock, action: Action
):
    action.type = "stake_deposit"
    action.source = block.data.source.as_str()
    action.destination = block.data.pool.as_str()
    action.amount = block.data.value.value
    action.staking_data = {"provider": "nominator"}


def _fill_nominator_pool_withdraw_request_action(
    block: NominatorPoolWithdrawRequestBlock, action: Action
):
    if block.data.payout_amount is None:
        action.type = "stake_withdrawal_request"
    else:
        action.type = "stake_withdrawal"
        action.amount = block.data.payout_amount.value
    action.staking_data = {"provider": "nominator"}
    action.source = block.data.source.as_str()
    action.destination = block.data.pool.as_str()


def block_to_action(block: Block, trace_id: str) -> Action:
    action = _base_block_to_action(block, trace_id)
    match block:
        case CallContractBlock():
            _fill_call_contract_action(block, action)
        case ContractDeployBlock():
            _fill_call_contract_action(block, action)
        case TonTransferBlock():
            _fill_ton_transfer_action(block, action)
        case NominatorPoolDepositBlock():
            _fill_nominator_pool_deposit_action(block, action)
        case NominatorPoolWithdrawRequestBlock():
            _fill_nominator_pool_withdraw_request_action(block, action)
        case DedustDepositLiquidityBlock():
            _fill_dedust_deposit_liquidity_action(block, action)
        case DedustDepositLiquidityPartialBlock():
            _fill_dedust_deposit_liquidity_partial_action(block, action)
        case JettonTransferBlock():
            _fill_jetton_transfer_action(block, action)
        case NftTransferBlock():
            _fill_nft_transfer_action(block, action)
        case NftDiscoveryBlock():
            _fill_nft_discovery_action(block, action)
        case NftMintBlock():
            _fill_nft_mint_action(block, action)
        case JettonBurnBlock():
            _fill_jetton_burn_action(block, action)
        case JettonMintBlock():
            _fill_jetton_mint_action(block, action)
        case JettonSwapBlock():
            _fill_jetton_swap_action(block, action)
        case DnsChangeRecordBlock():
            _fill_change_dns_record_action(block, action)
        case DnsDeleteRecordBlock():
            _fill_delete_dns_record_action(block, action)
        case DnsRenewBlock():
            _fill_dns_renew_action(block, action)
        case TONStakersDepositBlock():
            _fill_tonstakers_deposit_action(block, action)
        case TONStakersWithdrawRequestBlock():
            _fill_tonstakers_withdraw_request_action(block, action)
        case TONStakersWithdrawBlock():
            _fill_tonstakers_withdraw_action(block, action)
        case SubscribeBlock():
            _fill_subscribe_action(block, action)
        case DexDepositLiquidityBlock():
            _fill_dex_deposit_liquidity(block, action)
        case DexWithdrawLiquidityBlock():
            _fill_dex_withdraw_liquidity(block, action)
        case JVaultStakeBlock():
            _fill_jvault_stake(block, action)
        case JVaultUnstakeBlock():
            _fill_jvault_unstake(block, action)
        case JVaultClaimBlock():
            _fill_jvault_claim(block, action)
        case MultisigCreateOrderBlock():
            _fill_multisig_create_order(block, action)
        case MultisigApproveBlock():
            _fill_multisig_approve(block, action)
        case VestingSendMessageBlock():
            _fill_vesting_send_message(block, action)
        case VestingAddWhiteListBlock():
            _fill_vesting_add_whitelist(block, action)
        case UnsubscribeBlock():
            _fill_unsubscribe_action(block, action)
        case ElectionDepositStakeBlock():
            _fill_election_action(block, action)
        case ElectionRecoverStakeBlock():
            _fill_election_action(block, action)
        case AuctionBidBlock():
            _fill_auction_bid_action(block, action)
        case _:
            logger.warning(f"Unknown block type {block.btype} for trace {trace_id}")

    # Fill accounts
    action.accounts.append(action.source)
    action.accounts.append(action.source_secondary)
    action.accounts.append(action.destination)
    action.accounts.append(action.destination_secondary)

    # Fill extended tx hashes
    extended_tx_hashes = set(action.tx_hashes)
    if block.initiating_event_node is not None:
        extended_tx_hashes.add(block.initiating_event_node.get_tx_hash() or "")
        if not block.initiating_event_node.is_tick_tock:
            acc = block.initiating_event_node.message.transaction.account
            if acc not in action.accounts:
                logging.info(
                    f"Initiating transaction ({block.initiating_event_node.get_tx_hash()}) account not in accounts. Trace id: {trace_id}. Action id: {action.action_id}"
                )
            action.accounts.append(acc)
    action.extended_tx_hashes = list(extended_tx_hashes)

    action.accounts = list(set(a for a in action.accounts if a is not None))
    return action
