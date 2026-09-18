-- Physical WebSocket connections and logical application calls are distinct.
alter table model_attempts add column entity_kind text not null default 'request'
  check (entity_kind in ('request','websocket_connection','websocket_call'));
alter table model_attempts add column parent_attempt_id text references model_attempts(id) on delete cascade;
alter table model_attempts add column projection jsonb;
alter table model_attempts add column evidence_refs jsonb not null default '[]'::jsonb;
create index model_attempts_parent_idx on model_attempts(parent_attempt_id) where parent_attempt_id is not null;

-- Exactly one disposition for each observed message, including control/unknown.
-- No payload copies: these rows point at the immutable event index.
create table attempt_event_links (
  project_id uuid not null,
  parent_attempt_id text not null references model_attempts(id) on delete cascade,
  recording_id text not null,
  seq bigint not null,
  call_attempt_id text references model_attempts(id) on delete cascade,
  reason text not null,
  processor_version text not null,
  primary key(parent_attempt_id, recording_id, seq),
  foreign key(recording_id,seq) references recording_events(recording_id,seq) on delete cascade
);
create index attempt_event_links_call_idx on attempt_event_links(call_attempt_id,seq)
  where call_attempt_id is not null;
