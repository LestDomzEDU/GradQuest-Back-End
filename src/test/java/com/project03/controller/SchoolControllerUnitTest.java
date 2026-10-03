package com.project03.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.project03.model.School;
import com.project03.model.StudentPreference;
import com.project03.model.User;
import com.project03.repository.SchoolRepository;
import com.project03.repository.StudentPreferenceRepository;
import com.project03.service.CurrentUserService;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

class SchoolControllerUnitTest {

    private final SchoolRepository repo = mock(SchoolRepository.class);
    private final StudentPreferenceRepository prefRepo = mock(StudentPreferenceRepository.class);
    private final CurrentUserService currentUser = mock(CurrentUserService.class);
    private final Authentication auth = mock(Authentication.class);
    private final SchoolController controller = new SchoolController(repo, prefRepo, currentUser);

    private static School school(String name, String state, School.SchoolType type) {
        School s = new School();
        s.setName(name);
        s.setState(state);
        s.setType(type);
        return s;
    }

    @Test
    @DisplayName("top5 responds 401 when nobody is signed in")
    void top5_unauthenticated() {
        when(currentUser.require(auth))
            .thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> controller.getTop5Schools(auth))
            .isInstanceOf(ResponseStatusException.class);
        verifyNoInteractions(prefRepo, repo);
    }

    @Test
    @DisplayName("top5 returns 404 when the signed-in user has no saved preferences")
    void top5_noPreferences() {
        User user = new User();
        when(currentUser.require(auth)).thenReturn(user);
        when(prefRepo.findByUser(user)).thenReturn(Optional.empty());

        ResponseEntity<List<School>> resp = controller.getTop5Schools(auth);

        assertThat(resp.getStatusCode().value()).isEqualTo(404);
    }

    @Test
    @DisplayName("top5 ranks schools by the signed-in user's own preferences")
    void top5_usesSessionUserPreferences() {
        User user = new User();
        StudentPreference prefs = new StudentPreference();
        prefs.setState("CA");
        prefs.setSchoolType(StudentPreference.SchoolType.PUBLIC);
        when(currentUser.require(auth)).thenReturn(user);
        when(prefRepo.findByUser(user)).thenReturn(Optional.of(prefs));

        School best = school("Best", "CA", School.SchoolType.PUBLIC);
        School partial = school("Partial", "CA", School.SchoolType.PRIVATE);
        School none = school("None", "NY", School.SchoolType.PRIVATE);
        when(repo.findAll()).thenReturn(List.of(none, partial, best));

        List<School> result = controller.getTop5Schools(auth).getBody();

        assertThat(result).containsExactly(best, partial);
    }
}
