-- Durable, retryable retention and deletion propagation (platform/10 section 6).
alter table capture_runs
  add column if not exists state text not null default 'active',
  add column if not exists retention_until timestamptz,
  add column if not exists deleted_at timestamptz,
  add column if not exists deleted_by text;

update capture_runs
set retention_until = created_at + interval '365 days'
where retention_until is null;

alter table capture_runs
  alter column retention_until set default (now() + interval '365 days');

alter table recordings
  add column if not exists deletion_started_at timestamptz,
  add column if not exists deleted_at timestamptz,
  add column if not exists deleted_by text;

update recordings
set retention_until = created_at + interval '90 days'
where retention_until is null;

alter table recordings
  alter column retention_until set default (now() + interval '90 days');

alter table blobs
  add column if not exists state text not null default 'active';

do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'capture_runs_state_valid') then
    alter table capture_runs add constraint capture_runs_state_valid
      check (state in ('active','deleting','deleted'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'recordings_state_valid') then
    alter table recordings add constraint recordings_state_valid
      check (state in ('open','sealed','expiring','expired','deleting','deleted'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'blobs_state_valid') then
    alter table blobs add constraint blobs_state_valid
      check (state in ('active','deleting'));
  end if;
end $$;

-- A blob may be referenced by multiple Recording segments in one project.
-- This relation, rather than a payload table guess, is authoritative for erasure.
create table if not exists recording_blob_refs (
  recording_id text not null references recordings(id) on delete cascade,
  project_id uuid not null references projects(id),
  sha256 bytea not null,
  created_at timestamptz not null default now(),
  primary key (recording_id, sha256)
);
create index if not exists recording_blob_refs_blob_idx
  on recording_blob_refs (project_id, sha256);

-- Best-effort migration of references already materialized by older workers.
insert into recording_blob_refs(recording_id, project_id, sha256)
select distinct refs.recording_id, refs.project_id, refs.sha256
from (
  select e.recording_id, r.project_id, e.payload_sha256 as sha256
  from recording_events e join recordings r on r.id=e.recording_id
  where e.payload_sha256 is not null
  union
  select a.recording_id, a.project_id, a.request_body_ref
  from model_attempts a where a.request_body_ref is not null
  union
  select a.recording_id, a.project_id, a.response_body_ref
  from model_attempts a where a.response_body_ref is not null
  union
  select i.recording_id, i.project_id, i.resolved_input_ref
  from model_inferences i join recordings r on r.id=i.recording_id and r.project_id=i.project_id
  where i.resolved_input_ref is not null
) refs
on conflict do nothing;

update blobs b
set ref_count = refs.n
from (
  select project_id, sha256, count(*)::int as n
  from recording_blob_refs group by project_id, sha256
) refs
where b.project_id=refs.project_id and b.sha256=refs.sha256;

create table if not exists deletion_requests (
  id uuid primary key,
  project_id uuid not null references projects(id),
  requested_entity_type text not null check (requested_entity_type in ('recording','capture_run','session','retention')),
  requested_entity_id text not null,
  capture_run_id text not null references capture_runs(id),
  mode text not null default 'full' check (mode in ('full','evidence')),
  recording_id text,
  collector_id uuid references collectors(id),
  collector_request_id uuid references collector_requests(id),
  state text not null default 'pending' check (state in ('pending','waiting_workers','deleting_objects','local_pending','done','local_failed')),
  attempts int not null default 0,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  requested_by text not null,
  reason text,
  requested_at timestamptz not null default now(),
  remote_deleted_at timestamptz,
  completed_at timestamptz
);
create unique index if not exists deletion_requests_full_run_idx
  on deletion_requests(project_id, capture_run_id) where mode='full';
create unique index if not exists deletion_requests_evidence_recording_idx
  on deletion_requests(project_id, recording_id) where mode='evidence';
create index if not exists deletion_requests_ready_idx
  on deletion_requests(state, next_attempt_at);

-- Object deletes are materialized before execution so a process crash cannot
-- lose work between deleting an object and committing the relational tombstone.
create table if not exists deletion_objects (
  deletion_request_id uuid not null references deletion_requests(id) on delete cascade,
  object_key text not null,
  kind text not null check (kind in ('batch','blob','export')),
  state text not null default 'pending' check (state in ('pending','deleting','done')),
  attempts int not null default 0,
  lease_until timestamptz,
  next_attempt_at timestamptz not null default now(),
  last_error text,
  deleted_at timestamptz,
  primary key (deletion_request_id, object_key)
);
create index if not exists deletion_objects_ready_idx
  on deletion_objects(state, next_attempt_at, lease_until);
