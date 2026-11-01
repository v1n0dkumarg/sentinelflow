package dev.portfolio.sentinelflow;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record Incident(
        UUID id,
        String title,
        String severity,
        String status,
        Instant createdAt,
        String username,
        String sourceIp,
        List<UUID> evidenceEventIds,
        List<ResponseAction> actions) {

    public Incident {
        evidenceEventIds = List.copyOf(evidenceEventIds);
        actions = List.copyOf(actions);
    }

    public record ResponseAction(UUID id, String type, String summary, String approvalStatus) {
    }
}