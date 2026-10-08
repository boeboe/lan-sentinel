-- IDENTIFY_RAN records each operator identify run (docs/DATA_MODEL.md §7,
-- ADR 0009 / 0011). A CHECK constraint cannot be altered, so events is
-- rebuilt with the longer list (nothing references it) and its indexes
-- are created again.
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
        'DHCP_SERVER_DISCOVERED', 'DHCP_SERVER_UNEXPECTED', 'DHCP_SERVER_MAC_CHANGED', 'DHCP_CONFIG_CHANGED',
        'HOST_DESCRIBED', 'IDENTIFY_RAN'
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
