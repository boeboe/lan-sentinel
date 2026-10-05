-- LAN Sentinel initial schema. See docs/DATA_MODEL.md §3–§4.
-- Timestamps are UTC Unix milliseconds. Binding tables use first_seen
-- (inclusive), last_seen (last evidence, never NULL) and ended_at (NULL while
-- open, exclusive end once closed).

CREATE TABLE network_contexts (
    id         INTEGER PRIMARY KEY,
    interface  TEXT    NOT NULL UNIQUE,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    CHECK (last_seen >= first_seen)
) STRICT;

CREATE TABLE context_prefixes (
    id         INTEGER PRIMARY KEY,
    context_id INTEGER NOT NULL REFERENCES network_contexts (id),
    prefix     TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ended_at   INTEGER,
    CHECK (last_seen >= first_seen),
    CHECK (ended_at IS NULL OR ended_at >= first_seen)
) STRICT;

CREATE UNIQUE INDEX context_prefixes_open ON context_prefixes (context_id, prefix) WHERE ended_at IS NULL;

CREATE TABLE hosts (
    host_id              TEXT    PRIMARY KEY,
    context_id           INTEGER NOT NULL REFERENCES network_contexts (id),
    mac                  TEXT    NOT NULL,
    vendor               TEXT,
    locally_administered INTEGER NOT NULL DEFAULT 0 CHECK (locally_administered IN (0, 1)),
    presence             TEXT    NOT NULL CHECK (presence IN ('ACTIVE', 'RECENT', 'STALE', 'MISSING')),
    preferred_name       TEXT,
    manufacturer         TEXT,
    device_type          TEXT,
    first_seen           INTEGER NOT NULL,
    last_seen            INTEGER NOT NULL,
    tags                 TEXT    NOT NULL DEFAULT '[]',
    UNIQUE (context_id, mac),
    CHECK (last_seen >= first_seen)
) STRICT;

CREATE INDEX hosts_mac ON hosts (mac);

CREATE TABLE addresses (
    id         INTEGER PRIMARY KEY,
    context_id INTEGER NOT NULL REFERENCES network_contexts (id),
    host_id    TEXT    NOT NULL REFERENCES hosts (host_id),
    ip         TEXT    NOT NULL,
    family     INTEGER NOT NULL CHECK (family IN (4, 6)),
    conflict   INTEGER NOT NULL DEFAULT 0 CHECK (conflict IN (0, 1)),
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ended_at   INTEGER,
    CHECK (last_seen >= first_seen),
    CHECK (ended_at IS NULL OR ended_at >= first_seen)
) STRICT;

CREATE UNIQUE INDEX addresses_open ON addresses (host_id, ip) WHERE ended_at IS NULL;
CREATE INDEX addresses_point_in_time ON addresses (context_id, ip, first_seen);
CREATE INDEX addresses_host ON addresses (host_id, first_seen);

CREATE TABLE address_sources (
    address_id INTEGER NOT NULL REFERENCES addresses (id),
    source     TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (address_id, source),
    CHECK (last_seen >= first_seen)
) STRICT, WITHOUT ROWID;

CREATE TABLE names (
    id         INTEGER PRIMARY KEY,
    host_id    TEXT    NOT NULL REFERENCES hosts (host_id),
    name       TEXT    NOT NULL,
    name_type  TEXT    NOT NULL CHECK (name_type IN ('mdns', 'dhcp', 'dns_ptr', 'lldp', 'netbios')),
    source     TEXT    NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    ended_at   INTEGER,
    CHECK (last_seen >= first_seen),
    CHECK (ended_at IS NULL OR ended_at >= first_seen)
) STRICT;

CREATE UNIQUE INDEX names_open ON names (host_id, name_type, name) WHERE ended_at IS NULL;
CREATE INDEX names_name ON names (name);

CREATE TABLE services (
    id             INTEGER PRIMARY KEY,
    host_id        TEXT    NOT NULL REFERENCES hosts (host_id),
    proto          TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp')),
    port           INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state          TEXT    NOT NULL CHECK (state IN ('OPEN', 'REFUSED', 'TIMEOUT', 'UNREACHABLE', 'UNKNOWN')),
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    last_result_at INTEGER NOT NULL,
    UNIQUE (host_id, proto, port),
    CHECK (last_seen >= first_seen)
) STRICT;

CREATE TABLE identifications (
    id            INTEGER PRIMARY KEY,
    host_id       TEXT    NOT NULL REFERENCES hosts (host_id),
    field         TEXT    NOT NULL,
    value         TEXT    NOT NULL,
    confidence    REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    source        TEXT    NOT NULL,
    evidence_json TEXT    NOT NULL DEFAULT '{}',
    first_seen    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    UNIQUE (host_id, field, value, source),
    CHECK (last_seen >= first_seen)
) STRICT;

-- Raw evidence, compacted. host_id is a soft reference (NULL if unbound).
CREATE TABLE observations (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    context_id   INTEGER NOT NULL,
    source       TEXT    NOT NULL,
    mac          TEXT,
    ip           TEXT,
    hostname     TEXT,
    name_type    TEXT,
    service_json TEXT,
    meta_json    TEXT,
    host_id      TEXT
) STRICT;

CREATE INDEX observations_ts ON observations (ts);
CREATE INDEX observations_host ON observations (host_id, ts);

CREATE TABLE observation_rollups (
    id         INTEGER PRIMARY KEY,
    hour       INTEGER NOT NULL,
    context_id INTEGER NOT NULL,
    host_id    TEXT,
    source     TEXT    NOT NULL,
    mac        TEXT,
    ip         TEXT,
    count      INTEGER NOT NULL CHECK (count > 0),
    first_ts   INTEGER NOT NULL,
    last_ts    INTEGER NOT NULL,
    CHECK (last_ts >= first_ts)
) STRICT;

CREATE UNIQUE INDEX observation_rollups_key ON observation_rollups (
    hour, context_id, coalesce(host_id, ''), source, coalesce(mac, ''), coalesce(ip, '')
);
CREATE INDEX observation_rollups_hour ON observation_rollups (hour);
CREATE INDEX observation_rollups_host ON observation_rollups (host_id, hour);

-- Permanent history. evidence_json is a self-contained snapshot of the cause;
-- observation_id is informational and may point at a pruned row.
CREATE TABLE events (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    type            TEXT    NOT NULL CHECK (type IN (
        'HOST_DISCOVERED', 'HOST_DISAPPEARED', 'HOST_REAPPEARED',
        'IP_ADDED', 'IP_REMOVED', 'IP_CHANGED', 'MAC_MOVED',
        'HOSTNAME_ADDED', 'HOSTNAME_CHANGED', 'HOSTNAME_REMOVED',
        'SERVICE_OPENED', 'SERVICE_CLOSED', 'VENDOR_IDENTIFIED',
        'DUPLICATE_IP_DETECTED', 'DUPLICATE_IP_RESOLVED',
        'SCAN_STARTED', 'SCAN_COMPLETED', 'ACTIVE_DISABLED', 'ACTIVE_ENABLED',
        'INTERFACE_UP', 'INTERFACE_DOWN', 'SUBNET_CHANGED'
    )),
    severity        TEXT    NOT NULL CHECK (severity IN ('info', 'notice', 'warning')),
    context_id      INTEGER REFERENCES network_contexts (id),
    host_id         TEXT    REFERENCES hosts (host_id),
    related_host_id TEXT    REFERENCES hosts (host_id),
    old_value       TEXT,
    new_value       TEXT,
    cause           TEXT    NOT NULL,
    observation_id  INTEGER,
    evidence_json   TEXT    NOT NULL DEFAULT '{}',
    clock_synced    INTEGER NOT NULL CHECK (clock_synced IN (0, 1))
) STRICT;

CREATE INDEX events_ts ON events (ts);
CREATE INDEX events_host ON events (host_id, ts);
CREATE INDEX events_type ON events (type, ts);
CREATE INDEX events_context ON events (context_id, ts);

CREATE TABLE scans (
    id           INTEGER PRIMARY KEY,
    context_id   INTEGER NOT NULL REFERENCES network_contexts (id),
    kind         TEXT    NOT NULL,
    trigger      TEXT    NOT NULL CHECK (trigger IN ('scheduled', 'operator')),
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    targets      INTEGER NOT NULL DEFAULT 0,
    results_json TEXT    NOT NULL DEFAULT '{}'
) STRICT;

-- Operator state that must survive restarts (kill switch). DATA_MODEL.md §8.
CREATE TABLE runtime_state (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
