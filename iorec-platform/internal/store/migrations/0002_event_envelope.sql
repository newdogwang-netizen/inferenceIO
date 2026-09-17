-- Preserve the complete recorder event v1 envelope in the rebuildable event index.
alter table recording_events
  add column if not exists event_id uuid,
  add column if not exists raw_media_type text,
  add column if not exists raw_truncated boolean not null default false,
  add column if not exists confidence real,
  add column if not exists evidence jsonb not null default '[]'::jsonb,
  add column if not exists terminal_state text;

alter table recording_events
  add constraint recording_events_confidence_range
  check (confidence is null or (confidence >= 0 and confidence <= 1));

create unique index if not exists recording_events_event_id_idx
  on recording_events (recording_id, event_id)
  where event_id is not null;

