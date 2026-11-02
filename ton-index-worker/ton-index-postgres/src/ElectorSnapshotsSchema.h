#pragma once

namespace staking_history::postgres {
inline constexpr const char* SCHEMA_SQL = R"SQL(
CREATE TABLE IF NOT EXISTS public.elector_stake_states (
    mc_seqno bigint PRIMARY KEY,
    gen_utime bigint NOT NULL,
    elector_address tonaddr NOT NULL,
    code_hash text NOT NULL,
    data_hash text NOT NULL,
    previous_data_hash text NOT NULL,
    complete boolean NOT NULL,
    penalty_activity boolean NOT NULL,
    error text NOT NULL,
    applications_complete boolean NOT NULL,
    applications_error text NOT NULL
);
CREATE INDEX IF NOT EXISTS elector_stake_states_time_idx ON public.elector_stake_states(gen_utime,mc_seqno);
CREATE TABLE IF NOT EXISTS public.elector_frozen_elections (
    mc_seqno bigint NOT NULL REFERENCES public.elector_stake_states(mc_seqno) ON DELETE CASCADE,
    election_id bigint NOT NULL, vset_hash varchar NOT NULL,
    unfreeze_at bigint NOT NULL, stake_held bigint NOT NULL, total_stake numeric(38,0) NOT NULL,
    PRIMARY KEY(mc_seqno,election_id)
);
CREATE INDEX IF NOT EXISTS elector_frozen_elections_origin_idx
ON public.elector_frozen_elections(election_id,vset_hash,mc_seqno);
CREATE TABLE IF NOT EXISTS public.elector_stake_positions (
    mc_seqno bigint NOT NULL, election_id bigint NOT NULL,
    pubkey text NOT NULL, holder tonaddr NOT NULL, weight numeric(20,0) NOT NULL,
    stake numeric(38,0) NOT NULL, banned boolean NOT NULL, adnl text,
    PRIMARY KEY(mc_seqno,election_id,pubkey),
    FOREIGN KEY(mc_seqno,election_id) REFERENCES public.elector_frozen_elections ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS public.elector_applications (
    mc_seqno bigint PRIMARY KEY REFERENCES public.elector_stake_states ON DELETE CASCADE,
    election_id bigint NOT NULL, elect_close bigint NOT NULL,
    min_stake numeric(38,0) NOT NULL, total_stake numeric(38,0) NOT NULL,
    finished boolean NOT NULL, failed boolean NOT NULL
);
CREATE TABLE IF NOT EXISTS public.elector_application_participants (
    mc_seqno bigint NOT NULL REFERENCES public.elector_applications ON DELETE CASCADE,
    pubkey text NOT NULL, holder tonaddr NOT NULL, adnl text NOT NULL,
    stake numeric(38,0) NOT NULL, max_factor bigint NOT NULL,
    PRIMARY KEY(mc_seqno,pubkey)
);
CREATE OR REPLACE VIEW public.elector_frozen_positions AS
SELECT s.mc_seqno, s.gen_utime, e.election_id, e.vset_hash::text AS vset_hash,
       e.unfreeze_at, e.stake_held, p.pubkey, p.holder, p.weight, p.stake, p.banned
FROM public.elector_stake_states s
JOIN public.elector_frozen_elections e USING(mc_seqno)
JOIN public.elector_stake_positions p USING(mc_seqno,election_id)
WHERE s.complete;
CREATE TABLE IF NOT EXISTS public.validator_set_states (
    mc_seqno bigint PRIMARY KEY, gen_utime bigint NOT NULL,
    config_hash varchar NOT NULL, config_boc text NOT NULL
);
CREATE TABLE IF NOT EXISTS public.stake_holder_states (
    account tonaddr NOT NULL, mc_seqno bigint NOT NULL, gen_utime bigint NOT NULL,
    code_hash text NOT NULL, data_hash text NOT NULL,
    kind text NOT NULL, pool tonaddr, error text NOT NULL,
    PRIMARY KEY(account,mc_seqno)
);
)SQL";
}
