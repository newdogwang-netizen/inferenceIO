alter table collectors
  add column if not exists config_override jsonb,
  add column if not exists config_override_version bigint not null default 0
    check (config_override_version >= 0);
