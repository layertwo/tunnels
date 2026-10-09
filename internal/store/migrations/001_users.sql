create table users (
    sub        text primary key,
    handle     text unique not null,
    disabled   boolean not null default false,
    created_at timestamptz not null default now()
);
