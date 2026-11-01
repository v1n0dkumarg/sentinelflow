package dev.portfolio.sentinelflow;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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

    public SentinelController(SentinelService service) {
        this.service = service;
    }

    @GetMapping("/events")
    public List<SecurityEvent> events() {
        return service.events();
    }

    @GetMapping("/incidents")
    public List<Incident> incidents() {
        return service.incidents();
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
}