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

        @MockitoBean
        private AiArtifactService aiArtifacts;

        @Test
        void publicStylesheetsAreAvailableBeforeSignIn() throws Exception {
                mockMvc.perform(get("/styles.css")).andExpect(status().isOk());
                mockMvc.perform(get("/auth.css")).andExpect(status().isOk());
                mockMvc.perform(get("/workspace.css")).andExpect(status().isOk());
        }

    @Test
    void viewerCanReadButCannotCreateOrApproveResponseActions() throws Exception {
        when(service.events()).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/events"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/events").with(httpBasic("viewer", "local-viewer-change-me")))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/demo/suspicious-login").with(httpBasic("viewer", "local-viewer-change-me")))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/incidents/00000000-0000-0000-0000-000000000001/detection-rules")
                        .with(httpBasic("viewer", "local-viewer-change-me")))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/ai/artifacts/00000000-0000-0000-0000-000000000001/review")
                        .with(httpBasic("analyst", "local-analyst-change-me"))
                        .contentType("application/json").content("{\"decision\":\"APPROVED\"}"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/v1/incidents/00000000-0000-0000-0000-000000000001/actions/00000000-0000-0000-0000-000000000002/approval")
                        .with(httpBasic("analyst", "local-analyst-change-me")))
                .andExpect(status().isForbidden());
    }
}