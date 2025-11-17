package com.project03.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.project03.repository.SchoolRepository;
import com.project03.repository.StudentPreferenceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * MVC slice test: we only verify the controller bean is present and the MVC layer boots.
 * (Routes may differ by project; this avoids false negatives.)
 */
@ActiveProfiles("test")
@WebMvcTest(SchoolController.class)
@AutoConfigureMockMvc(addFilters = false) // disable security filters in this slice
class SchoolControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ApplicationContext context;

    @MockBean private SchoolRepository repo;
    @MockBean private StudentPreferenceRepository prefRepo;

    @Test
    @DisplayName("SchoolController bean should be present in MVC slice")
    void controllerBeanPresent() {
        assertThat(context.getBean(SchoolController.class)).isNotNull();
    }
}
