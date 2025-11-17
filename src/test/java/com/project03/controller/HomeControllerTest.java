package com.project03.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@ActiveProfiles("test")
@WebMvcTest(HomeController.class)
@AutoConfigureMockMvc(addFilters = false) // disable Spring Security filters for this slice
class HomeControllerTest {

    @Autowired private MockMvc mockMvc;

    @Test
    @DisplayName("GET / should return HTML landing page")
    void indexReturnsHtml() throws Exception {
        mockMvc.perform(get("/"))
               .andExpect(status().isOk())
               .andExpect(content().string(org.hamcrest.Matchers.containsString("Project 3 Back-End")));
    }
}
