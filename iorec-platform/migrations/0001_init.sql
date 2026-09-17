-- iorec platform schema v1. All business tables carry project_id.
create table if not exists tenants (
  id uuid primary key, name text not null, created_at timestamptz not null default now()
);
create table if not exists projects (
  id uuid primary key, tenant_id uuid not null references tenants(id),
  name text not null, settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique (tenant_id, name)
);
create table if not exists project_tokens (
  id uuid primary key, project_id uuid not null references projects(id),
  token_hash bytea not null unique, label text, created_at timestamptz not null default now(),
  revoked_at timestamptz
);
create table if not exists user_roles (
  project_id uuid not null references projects(id), subject text not null, role text not null,
  primary key (project_id, subject)
);

create table if not exists collectors (
  id uuid primary key, project_id uuid not null references projects(id),
  name text, version text, hostname text, os text,
  capabilities jsonb not null default '{}'::jsonb,
  effective_config jsonb, config_version bigint not null default 0,
  session_token_hash bytea, session_expires_at timestamptz,
  last_heartbeat_at timestamptz, health jsonb, status text not null default 'online',
  created_at timestamptz not null default now()
);
create index if not exists collectors_project_idx on collectors (project_id);

create table if not exists capture_runs (
  id text primary key, project_id uuid not null references projects(id), collector_id uuid,
  command text, cwd text, agent_kind text, agent_version text,
  started_at timestamptz, ended_at timestamptz, exit_code int,
  metadata jsonb not null default '{}'::jsonb,
  relation_revision bigint not null default 0, analysis_revision bigint not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists capture_runs_project_idx on capture_runs (project_id, created_at desc);

create table if not exists recordings (
  id text primary key, project_id uuid not null references projects(id),
  capture_run_id text not null references capture_runs(id),
  segment_no int not null default 0, schema_version int not null default 1,
  origin text not null default 'upload',
  state text not null default 'open',
  sequence_base bigint not null default 0 check (sequence_base >= 0),
  durable_seq bigint not null default 0, parsed_seq bigint not null default 0,
  final_seq bigint, manifest jsonb, coverage jsonb, coverage_revision bigint not null default 0,
  integrity_alerts jsonb not null default '[]'::jsonb,
  missing_blobs jsonb not null default '[]'::jsonb,
  sealed_at timestamptz, retention_until timestamptz,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  unique (capture_run_id, segment_no)
);
create index if not exists recordings_project_idx on recordings (project_id, created_at desc);

create table if not exists batches (
  recording_id text not null references recordings(id), batch_id text not null,
  first_seq bigint not null, last_seq bigint not null, event_count int not null,
  byte_length bigint not null, sha256 bytea not null, object_key text not null,
  received_at timestamptz not null default now(), parsed_at timestamptz,
  primary key (recording_id, batch_id),
  unique (recording_id, first_seq)
);

create table if not exists blobs (
  project_id uuid not null references projects(id), sha256 bytea not null,
  size bigint not null, media_type text, object_key text not null,
  first_seen_at timestamptz not null default now(), ref_count int not null default 0,
  primary key (project_id, sha256)
);

-- Derived index of raw events (rebuildable from batches). Payload kept inline when small.
create table if not exists recording_events (
  recording_id text not null references recordings(id), seq bigint not null,
  monotonic_ns bigint not null, wall_time timestamptz not null,
  source text not null, event text not null,
  task_id text, agent_session_id text, turn_id text, inference_id text, attempt_id text, connection_id text,
  parent_span_id text, pid int, container_id text,
  payload jsonb, payload_sha256 bytea, payload_size bigint, redaction jsonb,
  batch_id text not null,
  primary key (recording_id, seq)
);
create index if not exists recording_events_attempt_idx on recording_events (recording_id, attempt_id) where attempt_id is not null;
create index if not exists recording_events_inference_idx on recording_events (recording_id, inference_id) where inference_id is not null;
create index if not exists recording_events_event_idx on recording_events (recording_id, event);
create index if not exists recording_events_task_idx on recording_events (recording_id, task_id, seq) where task_id is not null;
create index if not exists recording_events_attempt_run_idx on recording_events (attempt_id, recording_id, seq) where attempt_id is not null;
create index if not exists recording_events_inference_run_idx on recording_events (inference_id, recording_id, seq) where inference_id is not null;

create table if not exists model_attempts (
  id text primary key, native_id text not null, recording_id text not null references recordings(id), project_id uuid not null,
  capture_run_id text not null, inference_id text,
  connection_id text, task_id text, session_id text, source text not null, protocol text, method text, url text, provider_host text,
  api_mode text, model text,
  started_at timestamptz, ended_at timestamptz, first_byte_at timestamptz,
  terminal_state text not null default 'unknown', status_code int, error_class text,
  request_headers jsonb, response_headers jsonb,
  request_body jsonb, request_body_ref bytea, response_body jsonb, response_body_ref bytea,
  sse_event_count int not null default 0, response_text text,
  usage jsonb, normalized jsonb, request_fingerprint bytea, input_hash bytea,
  first_seq bigint, last_seq bigint, processor_version text not null,
  pid int, container_id text, updated_at timestamptz not null default now()
);
create index if not exists model_attempts_recording_idx on model_attempts (recording_id, started_at);
create index if not exists model_attempts_run_idx on model_attempts (capture_run_id, started_at);
create index if not exists model_attempts_inference_idx on model_attempts (inference_id) where inference_id is not null;

create table if not exists model_inferences (
  id text primary key, native_id text, recording_id text not null, capture_run_id text not null, project_id uuid not null,
  status text not null, attempt_count int not null default 0, first_attempt_at timestamptz,
  model text, api_mode text, request_fingerprint bytea, input_hash bytea,
  request json, response json, usage jsonb, normalized jsonb,
  server_state text not null default 'none', resolved_input_ref bytea,
  task_id text, session_id text, turn_id text, pid int,
  evidence_refs jsonb not null default '[]'::jsonb, processor_version text not null,
  relation_revision bigint not null default 0, updated_at timestamptz not null default now()
);
create index if not exists model_inferences_run_idx on model_inferences (capture_run_id, first_attempt_at);
create index if not exists model_inferences_session_idx on model_inferences (session_id);
create index if not exists model_inferences_task_idx on model_inferences (task_id);

create table if not exists capture_tasks (
  id text primary key, project_id uuid not null, capture_run_id text not null references capture_runs(id),
  split_policy text not null, boundary_kind text not null, native_id text not null,
  session_ids jsonb not null default '[]'::jsonb, event_count bigint not null,
  first_seq bigint not null, last_seq bigint not null,
  first_seen_at timestamptz not null, last_seen_at timestamptz not null,
  updated_at timestamptz not null default now(),
  unique (capture_run_id, boundary_kind, native_id)
);
create index if not exists capture_tasks_run_idx on capture_tasks (capture_run_id, first_seq);

create table if not exists sessions (
  id text primary key, project_id uuid not null, capture_run_id text not null,
  kind text not null, native_id text, agent_kind text,
  parent_session_id text, role text not null default 'main',
  turns jsonb not null default '[]'::jsonb, inference_count int not null default 0,
  first_seen_at timestamptz, last_seen_at timestamptz,
  relation_revision bigint not null, superseded boolean not null default false
);
create index if not exists sessions_run_idx on sessions (capture_run_id, relation_revision);

create table if not exists relations (
  id bigserial primary key, project_id uuid not null, capture_run_id text not null,
  type text not null, from_id text not null, to_id text not null,
  status text not null, confidence real, evidence jsonb not null default '[]'::jsonb,
  revision bigint not null, superseded_by bigint, created_at timestamptz not null default now()
);
create index if not exists relations_from_idx on relations (capture_run_id, from_id, revision);
create index if not exists relations_to_idx on relations (capture_run_id, to_id, revision);

create table if not exists findings (
  id uuid primary key, project_id uuid not null, capture_run_id text, recording_id text,
  rule_id text not null, severity text not null, title text not null, detail jsonb not null default '{}'::jsonb,
  evidence_refs jsonb not null default '[]'::jsonb, evidence_key text not null,
  status text not null default 'open', analysis_revision bigint not null, processor_version text not null,
  created_at timestamptz not null default now(), reviewed_by text, reviewed_at timestamptz, review_note text,
  unique (project_id, rule_id, evidence_key)
);
create index if not exists findings_run_idx on findings (capture_run_id, status);

create table if not exists processing_jobs (
  id uuid primary key, project_id uuid not null,
  type text not null, recording_id text, capture_run_id text, input_ref jsonb not null default '{}'::jsonb,
  processor_version text not null, dedupe_key text not null unique,
  status text not null default 'pending', lease_owner text, lease_until timestamptz,
  attempts int not null default 0, last_error text, priority int not null default 0,
  traceparent text, created_at timestamptz not null default now(), started_at timestamptz, finished_at timestamptz
);
create index if not exists processing_jobs_ready_idx on processing_jobs (status, priority desc, created_at) where status in ('pending','leased');
create index if not exists processing_jobs_recording_idx on processing_jobs (recording_id, type);

create table if not exists assembly_state (
  capture_run_id text not null, stream_key text not null, recording_id text not null,
  state jsonb not null, last_seq bigint not null, version bigint not null default 1,
  primary key (capture_run_id, stream_key)
);

create table if not exists collector_requests (
  id uuid primary key, collector_id uuid not null references collectors(id), project_id uuid not null,
  type text not null, payload jsonb not null default '{}'::jsonb, status text not null default 'pending',
  result jsonb, created_by text, created_at timestamptz not null default now(),
  delivered_at timestamptz, delivery_attempts int not null default 0,
  expires_at timestamptz, finished_at timestamptz
);
create index if not exists collector_requests_pending_idx on collector_requests (collector_id, status);
create index if not exists collector_requests_dispatch_idx on collector_requests (collector_id, delivered_at, created_at)
  where status in ('pending','delivered','acked');

create table if not exists notifications_outbox (
  id bigserial primary key, project_id uuid not null,
  entity_type text not null, entity_id text not null, kind text not null,
  revision bigint, created_at timestamptz not null default now()
);
create index if not exists outbox_project_idx on notifications_outbox (project_id, id);

create table if not exists audit_log (
  id bigserial primary key, project_id uuid, subject text not null, action text not null,
  entity_type text, entity_id text, detail jsonb, created_at timestamptz not null default now()
);
create or replace function audit_log_immutable() returns trigger language plpgsql as $$
begin raise exception 'audit_log is append-only'; end $$;
drop trigger if exists audit_log_no_update on audit_log;
create trigger audit_log_no_update before update or delete on audit_log for each row execute function audit_log_immutable();
