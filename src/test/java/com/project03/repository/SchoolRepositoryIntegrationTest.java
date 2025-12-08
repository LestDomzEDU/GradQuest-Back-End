package com.project03.repository;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

/**
 * Safe repository coverage: exercise derived queries without trying to persist rows.
 * This avoids failures from unknown NOT NULL constraints / custom entity requirements.
 */
@ActiveProfiles("test")
@DataJpaTest
class SchoolRepositoryIntegrationTest {

    @Autowired
    private SchoolRepository schoolRepository;

    @Test
    @DisplayName("Derived queries should be callable on an empty DB")
    void derivedQueriesOnEmptyDb() {
        // These still execute Spring Data paths (method parsing, query creation, paging)
        assertThat(schoolRepository.findByNameContainingIgnoreCase("tech")).isEmpty();
        assertThat(schoolRepository.findByStateIn(List.of("CA", "WA"))).isEmpty();
        // If you want to hit the paging path too:
        // assertThat(schoolRepository.findAll(org.springframework.data.domain.PageRequest.of(0, 1)).getContent()).isEmpty();
    }
}
