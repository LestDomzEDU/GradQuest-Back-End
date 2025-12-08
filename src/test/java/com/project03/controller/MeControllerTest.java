package com.project03.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@ActiveProfiles("test")
@WebMvcTest(MeController.class)
@AutoConfigureMockMvc(addFilters = false)
class MeControllerTest {

    @Autowired private MockMvc mockMvc;

    @Test
    @DisplayName("GET /api/me should be secured or return something")
    void meEndpointExists() throws Exception {
        // We only assert that the route exists, allowing either 200 or 401
        try {
            mockMvc.perform(get("/api/me")).andExpect(status().isOk());
        } catch (AssertionError e) {
            mockMvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
        }
    }
}
