CREATE TABLE ai_artifacts (
    id UUID PRIMARY KEY,
    artifact_type VARCHAR(32) NOT NULL CHECK (artifact_type IN ('DETECTION_RULE', 'PLAYBOOK')),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    content JSONB NOT NULL,
    status VARCHAR(24) NOT NULL CHECK (status IN ('DRAFT', 'APPROVED', 'REJECTED')),
    created_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ,
    reviewed_by VARCHAR(120)
);

CREATE INDEX idx_ai_artifacts_type_created ON ai_artifacts (artifact_type, created_at DESC);
CREATE INDEX idx_ai_artifacts_incident ON ai_artifacts (incident_id, created_at DESC);