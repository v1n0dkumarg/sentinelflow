package dev.portfolio.sentinelflow;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record AiArtifact(
        UUID id,
        Type type,
        UUID incidentId,
        JsonNode content,
        String status,
        Instant createdAt,
        Instant reviewedAt,
        String reviewedBy) {

    public enum Type {
        DETECTION_RULE,
        PLAYBOOK
    }

    public record DetectionRuleDraft(
            String name,
            String description,
            String severity,
            String query,
            String falsePositiveGuidance,
            List<String> validationSteps) {
    }

    public record PlaybookDraft(
            String name,
            String objective,
            List<PlaybookStep> steps,
            List<String> safetyNotes) {
    }

    public record PlaybookStep(String title, String instruction, String expectedOutcome) {
    }
}