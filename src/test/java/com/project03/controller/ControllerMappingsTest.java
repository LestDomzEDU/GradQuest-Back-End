package com.project03.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.project03.repository.ApplicationRepository;
import com.project03.repository.ReminderRepository;
import com.project03.repository.SchoolRepository;
import com.project03.repository.StudentPreferenceRepository;
import com.project03.repository.UserRepository;

/**
 * Verifies that selected controllers are registered with Spring MVC
 * and contribute at least one handler method each.
 */
@ActiveProfiles("test")
@WebMvcTest({
        HomeController.class,
        MeController.class,
        OAuthDebugController.class,
        OAuthFinalController.class,
        ReminderController.class,
        SchoolController.class,
        StudentPreferenceController.class,
        TestingController.class,
        UserController.class
})
@AutoConfigureMockMvc(addFilters = false)
class ControllerMappingsTest {

    @Autowired
    private RequestMappingHandlerMapping mapping;

    // Mock dependencies that some controllers autowire
    @MockBean private SchoolRepository schoolRepository;
    @MockBean private StudentPreferenceRepository studentPreferenceRepository;
    @MockBean private ApplicationRepository applicationRepository;
    @MockBean private ReminderRepository reminderRepository;
    @MockBean private UserRepository userRepository;

    @Test
    @DisplayName("Controllers are present and have at least one registered handler method")
    void controllersHaveHandlerMethods() {
        Collection<HandlerMethod> handlers =
                mapping.getHandlerMethods().values(); // Map<RequestMappingInfo, HandlerMethod>

        assertThat(handlers.stream().anyMatch(h -> h.getBeanType().equals(HomeController.class)))
            .as("HomeController has mappings").isTrue();

        assertThat(handlers.stream().anyMatch(h -> h.getBeanType().equals(MeController.class)))
            .as("MeController has mappings").isTrue();

        assertThat(handlers.stream().anyMatch(h -> h.getBeanType().equals(SchoolController.class)))
            .as("SchoolController has mappings").isTrue();

        assertThat(handlers.stream().anyMatch(h -> h.getBeanType().equals(UserController.class)))
            .as("UserController has mappings").isTrue();
    }
}
