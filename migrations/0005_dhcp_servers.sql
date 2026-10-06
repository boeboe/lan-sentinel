-- Passive DHCP server monitoring (FR-PA-7). One row per server identity,
-- relay and sender seen on an interface: server_id is option 54 ('' when a
-- reply had none or an invalid one: the identity is unknown), relay the
-- giaddr ('' when the reply was not relayed), mac and ip the frame's sender
-- (the server, or the relay that forwarded the reply; ip '' when unusable).
-- status is the allowlist verdict at the last reply; config_json the router,
-- dns and subnet_mask last advertised. See docs/DATA_MODEL.md §5.6.
CREATE TABLE dhcp_servers (
    id          INTEGER PRIMARY KEY,
    context_id  INTEGER NOT NULL REFERENCES network_contexts (id),
    server_id   TEXT    NOT NULL,
    relay       TEXT    NOT NULL,
    mac         TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    host_id     TEXT    REFERENCES hosts (host_id),
    status      TEXT    NOT NULL CHECK (status IN ('allowed', 'unexpected', 'unchecked')),
    config_json TEXT    NOT NULL DEFAULT '{}',
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    UNIQUE (context_id, server_id, relay, mac),
    CHECK (last_seen >= first_seen)
) STRICT;

-- The DHCP server events (docs/DATA_MODEL.md §7). A CHECK constraint
-- cannot be altered, so events is rebuilt with the longer list (nothing
-- references it) and its indexes are created again.
CREATE TABLE events_rebuilt (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    type            TEXT    NOT NULL CHECK (type IN (
        'HOST_DISCOVERED', 'HOST_DISAPPEARED', 'HOST_REAPPEARED',
        'IP_ADDED', 'IP_REMOVED', 'IP_CHANGED', 'MAC_MOVED',
        'HOSTNAME_ADDED', 'HOSTNAME_CHANGED', 'HOSTNAME_REMOVED',
        'SERVICE_OPENED', 'SERVICE_CLOSED', 'VENDOR_IDENTIFIED',
        'DUPLICATE_IP_DETECTED', 'DUPLICATE_IP_RESOLVED',
        'SCAN_STARTED', 'SCAN_COMPLETED', 'ACTIVE_DISABLED', 'ACTIVE_ENABLED',
        'INTERFACE_UP', 'INTERFACE_DOWN', 'SUBNET_CHANGED', 'DATABASE_RECREATED',
        'DHCP_SERVER_DISCOVERED', 'DHCP_SERVER_UNEXPECTED', 'DHCP_SERVER_MAC_CHANGED', 'DHCP_CONFIG_CHANGED'
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
    clock_sync      TEXT    NOT NULL DEFAULT 'unknown' CHECK (clock_sync IN ('synced', 'unsynced', 'unknown'))
) STRICT;

INSERT INTO events_rebuilt (id, ts, type, severity, context_id, host_id, related_host_id, old_value, new_value, cause,
    observation_id, evidence_json, clock_sync)
SELECT id, ts, type, severity, context_id, host_id, related_host_id, old_value, new_value, cause,
    observation_id, evidence_json, clock_sync FROM events;
DROP TABLE events;
ALTER TABLE events_rebuilt RENAME TO events;

-- Dropping the table dropped its indexes (0001, 0002): the same again.
CREATE INDEX events_ts ON events (ts);
CREATE INDEX events_host ON events (host_id, ts);
CREATE INDEX events_type ON events (type, ts);
CREATE INDEX events_context ON events (context_id, ts);
CREATE INDEX events_related ON events (related_host_id, ts);
CREATE INDEX events_context_type ON events (context_id, type, ts);
CREATE INDEX events_old ON events (old_value);
CREATE INDEX events_new ON events (new_value);
CREATE INDEX events_evidence_ip ON events (json_extract(evidence_json, '$.ip'));
