CREATE TABLE security_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    username VARCHAR(120) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    event_type VARCHAR(80) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    detail VARCHAR(1000) NOT NULL
);

CREATE INDEX idx_security_events_occurred_at ON security_events (occurred_at DESC);
CREATE INDEX idx_security_events_identity ON security_events (username, occurred_at DESC);
CREATE INDEX idx_security_events_source ON security_events (source_ip, occurred_at DESC);

CREATE TABLE incidents (
    id UUID PRIMARY KEY,
    title VARCHAR(240) NOT NULL,
    severity VARCHAR(24) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    username VARCHAR(120) NOT NULL,
    source_ip VARCHAR(64) NOT NULL
);

CREATE INDEX idx_incidents_created_at ON incidents (created_at DESC);

CREATE TABLE incident_evidence (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES security_events(id),
    position INTEGER NOT NULL,
    PRIMARY KEY (incident_id, event_id),
    UNIQUE (incident_id, position)
);

CREATE TABLE response_actions (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(64) NOT NULL,
    summary VARCHAR(300) NOT NULL,
    approval_status VARCHAR(24) NOT NULL CHECK (approval_status IN ('PENDING', 'APPROVED', 'REJECTED'))
);

CREATE INDEX idx_response_actions_incident ON response_actions (incident_id);