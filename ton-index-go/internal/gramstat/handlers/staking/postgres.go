package staking

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Postgres struct{ DSN string }

const observationSelect = `SELECT s.mc_seqno,s.gen_utime,s.elector_address::text,
s.code_hash,s.data_hash,s.previous_data_hash,s.complete,s.penalty_activity,s.error,
s.applications_complete,a.election_id,a.finished,a.failed,a.total_stake::text
FROM public.elector_stake_states s LEFT JOIN public.elector_applications a USING(mc_seqno) `

func readObservation(ctx context.Context, tx pgx.Tx, suffix string, args ...any) (*Observation, error) {
	var o Observation
	var applicationID *uint32
	var finished, failed *bool
	var total *string
	if err := tx.QueryRow(ctx, observationSelect+suffix, args...).Scan(
		&o.MC, &o.Time, &o.Address, &o.CodeHash, &o.DataHash, &o.PreviousHash,
		&o.Complete, &o.PenaltyActivity, &o.Error, &o.ApplicationsComplete,
		&applicationID, &finished, &failed, &total); err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if applicationID != nil {
		o.Applications = &Applications{ID: *applicationID, Finished: *finished, Failed: *failed, Total: *total}
	}
	if !o.Complete {
		return &o, nil
	}
	rows, err := tx.Query(ctx, `SELECT e.election_id,e.vset_hash,e.unfreeze_at,e.total_stake::text,
p.pubkey,p.holder::text,p.stake::text,p.weight::text,p.banned,p.adnl
FROM public.elector_frozen_elections e
LEFT JOIN public.elector_stake_positions p USING(mc_seqno,election_id)
WHERE e.mc_seqno=$1 ORDER BY e.election_id,p.pubkey`, o.MC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Election
		var pubkey, holder, stake, weight, adnl *string
		var banned *bool
		if err := rows.Scan(&e.ID, &e.Hash, &e.UnfreezeAt, &e.Total, &pubkey, &holder, &stake, &weight, &banned, &adnl); err != nil {
			return nil, err
		}
		if len(o.Elections) == 0 || o.Elections[len(o.Elections)-1].ID != e.ID {
			o.Elections = append(o.Elections, e)
		}
		if pubkey != nil {
			last := &o.Elections[len(o.Elections)-1]
			last.Positions = append(last.Positions, Position{
				Pubkey: *pubkey, Holder: *holder, Stake: *stake, Weight: *weight, Banned: *banned, ADNL: adnl,
			})
		}
	}
	return &o, rows.Err()
}

func (p Postgres) Collect(ctx context.Context, from, to time.Time) ([]Point, error) {
	if p.DSN == "" {
		return nil, fmt.Errorf("GRAMSTAT_PG_DSN is required for staking")
	}
	cfg, err := pgx.ParseConfig(p.DSN)
	if err != nil {
		return nil, fmt.Errorf("invalid GRAMSTAT_PG_DSN")
	}
	cfg.ConnectTimeout = 10 * time.Second
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "300000"
	cfg.RuntimeParams["timezone"] = "UTC"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background())
	var head int64
	if err = tx.QueryRow(ctx, `SELECT gen_utime FROM public.blocks WHERE workchain=-1 ORDER BY seqno DESC LIMIT 1`).Scan(&head); err != nil {
		return nil, err
	}
	cache := map[string]Origin{}
	var points []Point
	for day := from; day.Before(to); day = day.AddDate(0, 0, 1) {
		end := min(day.AddDate(0, 0, 1).Unix(), to.Unix(), head+1)
		if end <= day.Unix() {
			break
		}
		point := Point{Day: day.Format(time.DateOnly), Origins: map[string]Origin{}}
		if end < day.AddDate(0, 0, 1).Unix() {
			point.Partial = 1
		}
		err = tx.QueryRow(ctx, `SELECT seqno,gen_utime FROM public.blocks WHERE workchain=-1 AND gen_utime<$1 ORDER BY gen_utime DESC,seqno DESC LIMIT 1`, end).Scan(&point.AnchorMC, &point.AnchorTime)
		if err != nil {
			return nil, err
		}
		point.State, err = readObservation(ctx, tx, `WHERE s.mc_seqno<=$1 ORDER BY s.mc_seqno DESC LIMIT 1`, point.AnchorMC)
		if err != nil {
			return nil, err
		}
		if point.State != nil && point.State.Complete {
			for _, e := range point.State.Elections {
				key := electionKey(e)
				o, ok := cache[key]
				if !ok {
					first, err := readObservation(ctx, tx, `JOIN public.elector_frozen_elections e ON e.mc_seqno=s.mc_seqno
WHERE e.election_id=$1 AND upper(e.vset_hash)=upper($2) ORDER BY e.mc_seqno LIMIT 1`, e.ID, e.Hash)
					if err != nil {
						return nil, err
					}
					if first != nil {
						o.First = *first
						o.Previous, err = readObservation(ctx, tx, `WHERE s.mc_seqno<$1 ORDER BY s.mc_seqno DESC LIMIT 1`, first.MC)
						if err != nil {
							return nil, err
						}
					}
					cache[key] = o
				}
				point.Origins[key] = o
			}
			addresses := []string{}
			for _, e := range point.State.Elections {
				for _, position := range e.Positions {
					addresses = append(addresses, position.Holder)
				}
			}
			rows, err := tx.Query(ctx, `SELECT DISTINCT ON (account) account::text,kind,pool::text,error FROM public.stake_holder_states
WHERE account=ANY($1::tonaddr[]) AND mc_seqno<=$2 ORDER BY account,mc_seqno DESC`, addresses, point.AnchorMC)
			if err != nil {
				return nil, err
			}
			point.State.Holders = nil
			for rows.Next() {
				var h Holder
				if err = rows.Scan(&h.Address, &h.Kind, &h.Pool, &h.Error); err != nil {
					rows.Close()
					return nil, err
				}
				point.State.Holders = append(point.State.Holders, h)
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				return nil, err
			}
		}
		points = append(points, point)
	}
	return points, tx.Commit(ctx)
}
