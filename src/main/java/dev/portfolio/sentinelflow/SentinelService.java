package dev.portfolio.sentinelflow;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import jakarta.annotation.PostConstruct;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SentinelService {
    private final JdbcTemplate jdbc;

    public SentinelService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostConstruct
    void seedDemoEvents() {
        Integer eventCount = jdbc.queryForObject("SELECT COUNT(*) FROM security_events", Integer.class);
        if (eventCount == null || eventCount == 0) {
            addEvent("maya.chen", "10.24.8.12", "authentication", "success", "VPN sign-in from managed device");
            addEvent("ops-bot", "10.24.2.19", "process", "success", "Scheduled inventory completed");
            addEvent("maya.chen", "198.51.100.42", "authentication", "failure", "Invalid password");
        }
    }

    @Cacheable("sentinel-events")
    public List<SecurityEvent> events() {
        return jdbc.query("SELECT id, occurred_at, username, source_ip, event_type, outcome, detail "
                        + "FROM security_events ORDER BY occurred_at DESC",
                (rs, row) -> new SecurityEvent(UUID.fromString(rs.getString("id")),
                        rs.getTimestamp("occurred_at").toInstant(), rs.getString("username"),
                        rs.getString("source_ip"), rs.getString("event_type"), rs.getString("outcome"),
                        rs.getString("detail")));
    }

    @Cacheable("sentinel-incidents")
    public List<Incident> incidents() {
        return jdbc.query("SELECT id FROM incidents ORDER BY created_at DESC",
                (rs, row) -> loadIncident(UUID.fromString(rs.getString("id"))));
    }

    @Transactional
    @CacheEvict(cacheNames = {"sentinel-events", "sentinel-incidents"}, allEntries = true)
    public synchronized Incident simulateSuspiciousLogin() {
        String user = "maya.chen";
        String ip = "198.51.100.42";
        List<SecurityEvent> evidence = new ArrayList<>();
        evidence.add(addEvent(user, ip, "authentication", "failure", "Synthetic repeated-login scenario: attempt 1 of 4"));
        evidence.add(addEvent(user, ip, "authentication", "failure", "Synthetic repeated-login scenario: attempt 2 of 4"));
        evidence.add(addEvent(user, ip, "authentication", "failure", "Synthetic repeated-login scenario: attempt 3 of 4"));
        evidence.add(addEvent(user, ip, "authentication", "success", "Successful sign-in after repeated failures; synthetic event"));

        List<Incident.ResponseAction> actions = List.of(
                new Incident.ResponseAction(UUID.randomUUID(), "LOCAL_BLOCKLIST", "Add source IP to the demo-only blocklist", "PENDING"),
                new Incident.ResponseAction(UUID.randomUUID(), "NOTIFY_SOC", "Send a notification to the mock SOC inbox", "PENDING"));
        UUID incidentId = UUID.randomUUID();
        Instant createdAt = Instant.now();
        jdbc.update("INSERT INTO incidents (id, title, severity, status, created_at, username, source_ip) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)",
            incidentId, "Repeated failures followed by successful sign-in", "HIGH", "NEW", createdAt, user, ip);
        for (int index = 0; index < evidence.size(); index++) {
            jdbc.update("INSERT INTO incident_evidence (incident_id, event_id, position) VALUES (?, ?, ?)",
                incidentId, evidence.get(index).id(), index);
        }
        for (Incident.ResponseAction action : actions) {
            jdbc.update("INSERT INTO response_actions (id, incident_id, action_type, summary, approval_status) "
                    + "VALUES (?, ?, ?, ?, ?)",
                action.id(), incidentId, action.type(), action.summary(), action.approvalStatus());
        }
        return new Incident(incidentId, "Repeated failures followed by successful sign-in", "HIGH", "NEW",
            createdAt, user, ip, evidence.stream().map(SecurityEvent::id).toList(), actions);
    }

        @Transactional
        @CacheEvict(cacheNames = "sentinel-incidents", allEntries = true)
    public synchronized Incident decideAction(UUID incidentId, UUID actionId, String decision) {
        if (!decision.equals("APPROVED") && !decision.equals("REJECTED")) {
            throw new IllegalArgumentException("Decision must be APPROVED or REJECTED");
        }
        int changed = jdbc.update("UPDATE response_actions SET approval_status = ? "
                + "WHERE id = ? AND incident_id = ? AND approval_status = 'PENDING'",
            decision, actionId, incidentId);
        if (changed == 0) {
            Boolean exists = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM incidents WHERE id = ?)",
                Boolean.class, incidentId);
            if (!Boolean.TRUE.equals(exists)) {
            throw new IllegalArgumentException("Incident not found");
            }
            throw new IllegalArgumentException("Response action is missing or no longer pending");
        }
        return loadIncident(incidentId);
    }

    private SecurityEvent addEvent(String username, String sourceIp, String eventType, String outcome, String detail) {
        SecurityEvent event = new SecurityEvent(UUID.randomUUID(), Instant.now(), username, sourceIp, eventType, outcome, detail);
        jdbc.update("INSERT INTO security_events (id, occurred_at, username, source_ip, event_type, outcome, detail) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?)",
            event.id(), event.timestamp(), event.username(), event.sourceIp(), event.eventType(), event.outcome(), event.detail());
        return event;
    }

        private Incident loadIncident(UUID id) {
        Incident incident = jdbc.queryForObject("SELECT id, title, severity, status, created_at, username, source_ip "
                + "FROM incidents WHERE id = ?",
            (rs, row) -> new Incident(UUID.fromString(rs.getString("id")), rs.getString("title"),
                rs.getString("severity"), rs.getString("status"), rs.getTimestamp("created_at").toInstant(),
                rs.getString("username"), rs.getString("source_ip"), List.of(), List.of()), id);
        List<UUID> evidence = jdbc.query("SELECT event_id FROM incident_evidence WHERE incident_id = ? ORDER BY position",
            (rs, row) -> UUID.fromString(rs.getString("event_id")), id);
        List<Incident.ResponseAction> actions = jdbc.query("SELECT id, action_type, summary, approval_status "
                + "FROM response_actions WHERE incident_id = ? ORDER BY action_type",
            (rs, row) -> new Incident.ResponseAction(UUID.fromString(rs.getString("id")),
                rs.getString("action_type"), rs.getString("summary"), rs.getString("approval_status")), id);
        return new Incident(incident.id(), incident.title(), incident.severity(), incident.status(), incident.createdAt(),
            incident.username(), incident.sourceIp(), evidence, actions);
        }
}