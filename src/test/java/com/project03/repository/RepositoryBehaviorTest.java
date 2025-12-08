package com.project03.repository;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ActiveProfiles;

import org.springframework.beans.factory.annotation.Autowired;

/**
 * Executes simple calls against Spring Data JPA proxies to increase coverage
 * without requiring seed data. This hits generated query code paths and paging.
 */
@ActiveProfiles("test")
@DataJpaTest
class RepositoryBehaviorTest {

    @Autowired private ApplicationRepository applicationRepository;
    @Autowired private ReminderRepository reminderRepository;
    @Autowired private SchoolRepository schoolRepository;
    @Autowired private StudentPreferenceRepository studentPreferenceRepository;
    @Autowired private UserRepository userRepository;

    @Test
    @DisplayName("Proxies should be wired and basic methods callable")
    void proxiesCallable() {
        // count() should run even on empty DB
        assertThat(applicationRepository.count()).isZero();
        assertThat(reminderRepository.count()).isZero();
        assertThat(schoolRepository.count()).isZero();
        assertThat(studentPreferenceRepository.count()).isZero();
        assertThat(userRepository.count()).isZero();

        // paging path (executes repository paging code)
        Pageable firstPage = PageRequest.of(0, 1);
        assertThat(schoolRepository.findAll(firstPage).getContent()).isEmpty();

        // derived queries with safe inputs (exercise method dispatch / parsing)
        assertThat(schoolRepository.findByNameContainingIgnoreCase("")).isEmpty();
        assertThat(schoolRepository.findByStateIn(List.of())).isEmpty();
    }
}
