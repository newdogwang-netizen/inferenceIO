-- Persist blob publication intent before touching the object store so an API
-- crash cannot leave sensitive, unowned content-addressed objects behind.
alter table blobs drop constraint if exists blobs_state_valid;
alter table blobs add constraint blobs_state_valid
  check (state in ('uploading','active','deleting'));

create index if not exists blobs_stale_upload_idx
  on blobs (first_seen_at)
  where state = 'uploading';
