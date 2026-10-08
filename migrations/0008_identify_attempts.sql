-- Once-per-MAC identification attempts (ADR 0011, FR-AC-11). Success and
-- failure both consume the attempt. The correlator is the only writer.
CREATE TABLE identify_attempts (
    host_id      TEXT    NOT NULL REFERENCES hosts (host_id),
    probe        TEXT    NOT NULL,
    result       TEXT    NOT NULL CHECK (result IN ('ok', 'timeout', 'refused', 'malformed')),
    attempted_at INTEGER NOT NULL,
    trigger      TEXT    NOT NULL CHECK (trigger IN ('scheduled', 'operator')),
    actor        TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, probe)
) STRICT;

CREATE INDEX identify_attempts_probe ON identify_attempts (probe, attempted_at);
