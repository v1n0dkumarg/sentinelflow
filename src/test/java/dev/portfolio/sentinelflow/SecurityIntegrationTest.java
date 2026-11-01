package dev.portfolio.sentinelflow;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@WebMvcTest(SentinelController.class)
@Import(SecurityConfiguration.class)
class SecurityIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

        @MockitoBean
    private SentinelService service;

    @Test
    void viewerCanReadButCannotCreateOrApproveResponseActions() throws Exception {
        when(service.events()).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/events"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/events").with(httpBasic("viewer", "local-viewer-change-me")))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/demo/suspicious-login").with(httpBasic("viewer", "local-viewer-change-me")))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/incidents/00000000-0000-0000-0000-000000000001/actions/00000000-0000-0000-0000-000000000002/approval")
                        .with(httpBasic("analyst", "local-analyst-change-me")))
                .andExpect(status().isForbidden());
    }
}