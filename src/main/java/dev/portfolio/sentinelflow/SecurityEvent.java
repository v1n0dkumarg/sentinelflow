package dev.portfolio.sentinelflow;

import java.time.Instant;
import java.util.UUID;

public record SecurityEvent(
        UUID id,
        Instant timestamp,
        String username,
        String sourceIp,
        String eventType,
        String outcome,
        String detail) {
}