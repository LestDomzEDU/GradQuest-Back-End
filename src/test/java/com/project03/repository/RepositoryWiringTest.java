package com.project03.repository;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import org.springframework.beans.factory.annotation.Autowired;

@ActiveProfiles("test")
@DataJpaTest
class RepositoryWiringTest {

    @Autowired private ApplicationRepository applicationRepository;
    @Autowired private ReminderRepository reminderRepository;
    @Autowired private SchoolRepository schoolRepository;
    @Autowired private StudentPreferenceRepository studentPreferenceRepository;
    @Autowired private UserRepository userRepository;

    @Test
    @DisplayName("All Spring Data repositories should be present in the application context")
    void repositoriesAreLoaded() {
        assertThat(applicationRepository).isNotNull();
        assertThat(reminderRepository).isNotNull();
        assertThat(schoolRepository).isNotNull();
        assertThat(studentPreferenceRepository).isNotNull();
        assertThat(userRepository).isNotNull();
    }
}
