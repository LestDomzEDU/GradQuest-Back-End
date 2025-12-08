package com.project03.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.project03.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

@ActiveProfiles("test")
@DataJpaTest
class UserRepositoryIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Save and fetch a User by id")
    void saveAndFetchUser() {
        User u = new User();
        u.setEmail("test@example.com"); // email is @Column(nullable = false, unique = true)
        u.setName("Test User");

        User saved = userRepository.save(u);
        assertThat(saved.getId()).isNotNull();

        Optional<User> found = userRepository.findById(saved.getId());
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
        assertThat(found.get().getName()).isEqualTo("Test User");

        assertThat(userRepository.count()).isEqualTo(1);
    }
}
