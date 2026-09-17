alter table recording_events add column if not exists task_id text;
create index if not exists recording_events_task_idx
  on recording_events (recording_id, task_id, seq) where task_id is not null;

alter table model_attempts add column if not exists task_id text;
alter table model_attempts add column if not exists session_id text;
alter table model_inferences add column if not exists task_id text;
create index if not exists model_inferences_task_idx
  on model_inferences (task_id) where task_id is not null;

create table if not exists capture_tasks (
  id text primary key,
  project_id uuid not null,
  capture_run_id text not null references capture_runs(id),
  split_policy text not null,
  boundary_kind text not null,
  native_id text not null,
  session_ids jsonb not null default '[]'::jsonb,
  event_count bigint not null,
  first_seq bigint not null,
  last_seq bigint not null,
  first_seen_at timestamptz not null,
  last_seen_at timestamptz not null,
  updated_at timestamptz not null default now(),
  unique (capture_run_id, boundary_kind, native_id)
);
create index if not exists capture_tasks_run_idx
  on capture_tasks (capture_run_id, first_seq);
