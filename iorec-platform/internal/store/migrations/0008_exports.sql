create table if not exists exports (
  id uuid primary key,
  project_id uuid not null references projects(id),
  capture_run_id text not null references capture_runs(id),
  format text not null check (format in ('normalized-jsonl')),
  state text not null default 'pending' check (state in ('pending','running','ready','failed','expired')),
  object_key text,
  filename text not null,
  media_type text not null,
  sha256 bytea,
  byte_length bigint check (byte_length is null or byte_length >= 0),
  expires_at timestamptz not null,
  created_by text not null,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  last_error text
);
create index if not exists exports_project_idx on exports (project_id, created_at desc);
create index if not exists exports_expiry_idx on exports (state, expires_at) where state = 'ready';
