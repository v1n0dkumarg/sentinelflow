package dev.portfolio.sentinelflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class SentinelServiceTest {
    @Test
    void suspiciousLoginCreatesIncidentWithPendingMockActions() {
        SentinelService service = new SentinelService(mock(JdbcTemplate.class));

        Incident incident = service.simulateSuspiciousLogin();

        assertEquals("HIGH", incident.severity());
        assertEquals(4, incident.evidenceEventIds().size());
        assertEquals(2, incident.actions().size());
        assertEquals("PENDING", incident.actions().getFirst().approvalStatus());
    }

    @Test
    void rejectsUnsupportedApprovalDecision() {
        SentinelService service = new SentinelService(mock(JdbcTemplate.class));

        assertThrows(IllegalArgumentException.class,
            () -> service.decideAction(java.util.UUID.randomUUID(), java.util.UUID.randomUUID(), "EXECUTE"));
    }
}