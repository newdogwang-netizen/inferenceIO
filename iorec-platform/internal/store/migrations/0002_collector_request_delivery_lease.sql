alter table collector_requests
  add column if not exists delivery_attempts int not null default 0;

create index if not exists collector_requests_dispatch_idx
  on collector_requests (collector_id, delivered_at, created_at)
  where status in ('pending','delivered','acked');
