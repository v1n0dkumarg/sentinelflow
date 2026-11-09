package dev.portfolio.sentinelflow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest
@Testcontainers(disabledWithoutDocker = true)
class PersistenceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine")
            .withDatabaseName("sentinelflow")
            .withUsername("test")
            .withPassword("test");

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7.4-alpine"))
            .withExposedPorts(6379)
            .withCommand("redis-server", "--requirepass", "local-only-change-me");

    @Autowired
    private SentinelService service;

    @Autowired
    private AiArtifactService aiArtifacts;

    @Autowired
    private JdbcTemplate jdbc;

    @DynamicPropertySource
    static void configureInfrastructure(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", REDIS::getFirstMappedPort);
        registry.add("spring.data.redis.password", () -> "local-only-change-me");
    }

    @Test
    void migrationsSeedDataAndRedisCacheRemainConsistent() {
        assertEquals(3, service.events().size());
        assertEquals(3, service.events().size());

        Incident incident = service.simulateSuspiciousLogin();
        assertEquals(4, incident.evidenceEventIds().size());
        assertTrue(service.incidents().stream().anyMatch(item -> item.id().equals(incident.id())));

        Incident.ResponseAction action = incident.actions().getFirst();
        Incident updated = service.decideAction(incident.id(), action.id(), "APPROVED");
        assertEquals("APPROVED", updated.actions().stream()
                .filter(candidate -> candidate.id().equals(action.id())).findFirst().orElseThrow().approvalStatus());

        UUID artifactId = UUID.randomUUID();
        jdbc.update("INSERT INTO ai_artifacts (id, artifact_type, incident_id, content, status, created_at) "
                + "VALUES (?, 'DETECTION_RULE', ?, ?::jsonb, 'DRAFT', ?)",
            artifactId, incident.id(), "{\"name\":\"Repeated login draft\"}", Timestamp.from(Instant.now()));
        assertEquals(1, aiArtifacts.list(AiArtifact.Type.DETECTION_RULE).size());
        AiArtifact reviewed = aiArtifacts.review(artifactId, "APPROVED", "analyst");
        assertEquals("APPROVED", reviewed.status());
        assertEquals("analyst", reviewed.reviewedBy());
    }
}