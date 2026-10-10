create table shares (
    owner_sub  text references users(sub) on delete cascade,
    tunnel     text not null default '',   -- '' = default tunnel
    kind       text check (kind in ('user','group')),
    grantee    text not null,
    created_at timestamptz not null default now(),
    primary key (owner_sub, tunnel, kind, grantee)
);
