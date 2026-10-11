create table machines (
    id         uuid primary key default gen_random_uuid(),
    handle     text not null,
    owner_kind text not null,
    owner_ref  text not null,
    client_id  text not null unique,
    disabled   boolean not null default false,
    created_at timestamptz not null default now(),
    created_by text not null
);

-- A handle is a machine's own within the machines table; the cross-namespace rule with users is
-- enforced under an advisory lock in the store's create paths.
create unique index machines_handle_key on machines (handle);
