-- A share is keyed by the site (owner sub + the site's handle + tunnel), not the tunnel name alone, so a
-- share on one of an owner's sites never admits another. Every share stored before this migration was a
-- person's own site, so its handle is the owner's users.handle.
alter table shares add column handle text;

update shares set handle = users.handle from users where users.sub = shares.owner_sub;

alter table shares alter column handle set not null;

-- The site's handle joins the key: two of an owner's sites may share the same tunnel name.
alter table shares drop constraint shares_pkey;
alter table shares add primary key (owner_sub, handle, tunnel, kind, grantee);
