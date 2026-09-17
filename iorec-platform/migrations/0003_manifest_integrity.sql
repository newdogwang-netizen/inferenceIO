alter table recordings
    add column if not exists manifest_sha256 bytea;

