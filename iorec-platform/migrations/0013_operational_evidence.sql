-- Operator-supplied benchmark results are annotations, never capture proof.
alter table capture_runs add column if not exists benchmark_result jsonb;

-- Process liveness is separate from successful job processing or queue drain.
create table if not exists worker_heartbeats (
    owner text primary key,
    pools jsonb not null,
    last_seen_at timestamptz not null default now()
);
create index if not exists worker_heartbeats_last_seen on worker_heartbeats(last_seen_at);
