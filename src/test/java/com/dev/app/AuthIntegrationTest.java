package com.dev.app;

import com.dev.app.dto.request.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the full authentication flow.
 *
 * Uses {@code @SpringBootTest} with {@code MockMvc} to test real HTTP
 * requests through the entire filter chain, including ShiroSessionFilter,
 * controllers, services, and database.
 *
 * <p>Activates the {@code dev} profile so that test users are seeded,
 * Swagger is enabled, and non-HTTPS cookies are permitted.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    //  Public endpoints

    @Test
    @Order(1)
    void hello_noAuth_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/hello"))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello World"));
    }

    @Test
    @Order(2)
    void swagger_noAuth_returns200() throws Exception {
        mockMvc.perform(get("/swagger-ui/index.html"))
                .andExpect(status().isOk());
    }

    @Test
    @Order(3)
    void apiDocs_noAuth_returns200() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    //  Unauthenticated access

    @Test
    @Order(10)
    void me_noAuth_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @Order(11)
    void adminDashboard_noAuth_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    // Login validation

    @Test
    @Order(20)
    void login_emptyBody_returns400WithFieldErrors() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.username").value("Username is required"))
                .andExpect(jsonPath("$.fieldErrors.password").value("Password is required"));
    }

    @Test
    @Order(21)
    void login_wrongPassword_returns401() throws Exception {
        // Password meets complexity rules but is wrong for the account
        LoginRequest request = new LoginRequest("admin", "Wr0ng!pass");
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    @Order(22)
    void login_unknownUser_returns401() throws Exception {
        // Password meets complexity rules but account does not exist
        LoginRequest request = new LoginRequest("nonexistent", "Unkn0wn!pass");
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    //  Full auth flow: admin user

    @Test
    @Order(30)
    void fullFlow_adminUser() throws Exception {
        // 1. Login as admin
        LoginRequest loginRequest = new LoginRequest("admin", "Admin123!");
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.isAdmin").value(true))
                .andExpect(jsonPath("$.roles").isArray())
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession();

        // 2. Access /auth/me with session
        mockMvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("admin"))
                .andExpect(jsonPath("$.isAdmin").value(true))
                .andExpect(jsonPath("$.isUser").value(true));

        // 3. Access admin dashboard
        mockMvc.perform(get("/api/v1/admin/dashboard").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome to the Admin Dashboard"))
                .andExpect(jsonPath("$.user").value("admin"));

        // 4. Logout
        mockMvc.perform(post("/api/v1/auth/logout").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));

        // 5. After logout, session is invalid — should get 401
        mockMvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isUnauthorized());
    }

    // Full auth flow: regular user (no admin access)

    @Test
    @Order(31)
    void fullFlow_regularUser_noAdminAccess() throws Exception {
        // 1. Login as ayoub
        LoginRequest loginRequest = new LoginRequest("ayoub", "Ayoub123!");
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("ayoub"))
                .andExpect(jsonPath("$.isAdmin").value(false))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession();

        // 2. Access /auth/me works
        mockMvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("ayoub"))
                .andExpect(jsonPath("$.isUser").value(true))
                .andExpect(jsonPath("$.isAdmin").value(false));

        // 3. Admin dashboard → 403 Forbidden
        mockMvc.perform(get("/api/v1/admin/dashboard").session(session))
                .andExpect(status().isForbidden());
    }
}
