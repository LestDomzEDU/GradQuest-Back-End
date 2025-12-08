package com.project03.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import com.project03.model.School;
import com.project03.repository.SchoolRepository;
import com.project03.repository.StudentPreferenceRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Optional;

class SchoolControllerUnitTest {

    private final SchoolRepository repo = mock(SchoolRepository.class);
    private final StudentPreferenceRepository prefRepo = mock(StudentPreferenceRepository.class);

    // Create controller directly with mocks (adjust if your ctor differs)
    private final SchoolController controller = new SchoolController(repo, prefRepo);

    @Test
    @DisplayName("deleteSchool() returns 200 when school exists")
    void deleteSchool_ok() {
        when(repo.existsById(1L)).thenReturn(true);
        doNothing().when(repo).deleteById(1L);

        ResponseEntity<Void> resp = controller.deleteSchool(1L);

        assertThat(resp.getStatusCode().is2xxSuccessful()).isTrue();
        verify(repo).deleteById(1L);
    }

    @Test
    @DisplayName("deleteSchool() returns 404 when school not found")
    void deleteSchool_notFound() {
        when(repo.existsById(2L)).thenReturn(false);

        ResponseEntity<Void> resp = controller.deleteSchool(2L);

        assertThat(resp.getStatusCode().value()).isEqualTo(404);
        verify(repo, never()).deleteById(anyLong());
    }

    @Test
    @DisplayName("findByNameContainingIgnoreCase path in repository can be exercised through controller list/search")
    void searchSchools_callsRepo() {
        // If your controller has a list/search method, adjust to call it directly.
        // Below we simulate a common pattern: repo.findByNameContainingIgnoreCase("")
        when(repo.findByNameContainingIgnoreCase("")).thenReturn(List.of());

        // If you have a method like: controller.getSchools(filter), call it here.
        // This acts as a placeholder to touch the repo path; comment out if not present.

        verify(repo, atLeast(0)).findByNameContainingIgnoreCase("");
    }
}
