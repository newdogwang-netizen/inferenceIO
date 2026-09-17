alter table capture_runs
  add column if not exists transport_proof jsonb,
  add column if not exists transport_proof_revision bigint not null default 0;

