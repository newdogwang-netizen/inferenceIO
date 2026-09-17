create index if not exists recording_events_attempt_run_idx
  on recording_events (attempt_id, recording_id, seq) where attempt_id is not null;
create index if not exists recording_events_inference_run_idx
  on recording_events (inference_id, recording_id, seq) where inference_id is not null;

create table assembly_state_run_v1 (
  capture_run_id text not null,
  stream_key text not null,
  recording_id text not null,
  state jsonb not null,
  last_seq bigint not null,
  version bigint not null default 1,
  primary key (capture_run_id, stream_key)
);

insert into assembly_state_run_v1(capture_run_id, stream_key, recording_id, state, last_seq, version)
select distinct on (r.capture_run_id, a.stream_key)
  r.capture_run_id, a.stream_key, a.recording_id, a.state, a.last_seq, a.version
from assembly_state a
join recordings r on r.id = a.recording_id
order by r.capture_run_id, a.stream_key, a.last_seq desc, a.recording_id;

drop table assembly_state;
alter table assembly_state_run_v1 rename to assembly_state;
