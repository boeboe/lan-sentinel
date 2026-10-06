-- Indexes for the read side (API, CLI): timelines and lookups that would
-- otherwise scan the events table (kept for 2 years) or names. Events are
-- few (state transitions only), so the extra indexes cost little to write.

-- Events of a host as the related side (conflicts, MAC moves, takeovers).
CREATE INDEX events_related ON events (related_host_id, ts);
-- The last INTERFACE_UP/DOWN of an interface.
CREATE INDEX events_context_type ON events (context_id, type, ts);
-- IP timelines: old value, new value or evidence IP.
CREATE INDEX events_old ON events (old_value);
CREATE INDEX events_new ON events (new_value);
CREATE INDEX events_evidence_ip ON events (json_extract(evidence_json, '$.ip'));

-- Every name of a host (the open-name index is partial), and names
-- matched case-insensitively.
CREATE INDEX names_host ON names (host_id, first_seen);
DROP INDEX names_name;
CREATE INDEX names_name ON names (name COLLATE NOCASE);
