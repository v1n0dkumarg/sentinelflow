package dev.portfolio.sentinelflow;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.core.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class SentinelController {
    private final SentinelService service;
    private final AiArtifactService aiArtifacts;

    public SentinelController(SentinelService service, AiArtifactService aiArtifacts) {
        this.service = service;
        this.aiArtifacts = aiArtifacts;
    }

    @GetMapping("/events")
    public List<SecurityEvent> events() {
        return service.events();
    }

    @GetMapping("/incidents")
    public List<Incident> incidents() {
        return service.incidents();
    }

    @GetMapping("/session")
    public SessionView session(Authentication authentication) {
        return new SessionView(authentication.getName(), authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority()).toList());
    }

    @GetMapping("/ai/artifacts")
    public List<AiArtifact> artifacts(@org.springframework.web.bind.annotation.RequestParam(required = false) AiArtifact.Type type) {
        return aiArtifacts.list(type);
    }

    @GetMapping("/ai/artifacts/{artifactId}")
    public AiArtifact artifact(@PathVariable UUID artifactId) {
        return aiArtifacts.get(artifactId);
    }

    @PostMapping("/incidents/{incidentId}/detection-rules")
    @ResponseStatus(HttpStatus.CREATED)
    public AiArtifact generateDetectionRule(@PathVariable UUID incidentId) {
        return aiArtifacts.generateDetectionRule(incidentId);
    }

    @PostMapping("/incidents/{incidentId}/playbooks")
    @ResponseStatus(HttpStatus.CREATED)
    public AiArtifact generatePlaybook(@PathVariable UUID incidentId) {
        return aiArtifacts.generatePlaybook(incidentId);
    }

    @PostMapping("/ai/artifacts/{artifactId}/review")
    public AiArtifact reviewArtifact(@PathVariable UUID artifactId, Authentication authentication,
            @Valid @RequestBody ApprovalRequest request) {
        return aiArtifacts.review(artifactId, request.decision(), authentication.getName());
    }

    @PostMapping("/demo/suspicious-login")
    @ResponseStatus(HttpStatus.CREATED)
    public Incident simulateSuspiciousLogin() {
        return service.simulateSuspiciousLogin();
    }

    @PostMapping("/incidents/{incidentId}/actions/{actionId}/approval")
    public Incident decideAction(@PathVariable UUID incidentId, @PathVariable UUID actionId,
            @Valid @RequestBody ApprovalRequest request) {
        try {
            return service.decideAction(incidentId, actionId, request.decision().toUpperCase());
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, exception.getMessage());
        }
    }

    public record ApprovalRequest(@NotBlank String decision) {
    }

    public record SessionView(String username, List<String> authorities) {
    }
}