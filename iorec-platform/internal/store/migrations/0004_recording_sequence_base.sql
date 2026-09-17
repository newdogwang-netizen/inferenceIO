alter table recordings
  add column if not exists sequence_base bigint not null default 0;

do $$ begin
  alter table recordings
    add constraint recordings_sequence_base_nonnegative check (sequence_base >= 0);
exception when duplicate_object then null;
end $$;
