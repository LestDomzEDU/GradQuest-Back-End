package com.project03.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.project03.model.School;
import com.project03.model.StudentPreference;
import com.project03.model.User;
import com.project03.repository.SchoolRepository;
import com.project03.repository.StudentPreferenceRepository;
import com.project03.service.CurrentUserService;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.math.BigDecimal;
import java.util.List;
import java.util.Comparator;
import java.util.stream.Collectors;

/**
 * controller for school matching functionality that will be neeeded for the student intake form
 * we can handel retrieving schools based on student criteria and returning top 5 matches here
 */

@RestController
@RequestMapping("/api/schools")
public class SchoolController {

    private final SchoolRepository repo;
    private final StudentPreferenceRepository preferenceRepo;
    private final CurrentUserService currentUser;

    public SchoolController(SchoolRepository repo, StudentPreferenceRepository preferenceRepo, CurrentUserService currentUser) {
        this.repo = repo;
        this.preferenceRepo = preferenceRepo;
        this.currentUser = currentUser;
    }

    /**
     * getting top 5 schools matching student's saved preferences
     * 
     * GET /api/schools/top5
     * 
     * this uses the student's saved preferences to match against available schools
     * 
     */
    @GetMapping("/top5")
    public ResponseEntity<List<School>> getTop5Schools(Authentication authentication) {
        User user = currentUser.require(authentication);
        
        // Retrieve student preferences
        StudentPreference preferences = preferenceRepo.findByUser(user)
                .orElse(null);
        
        if (preferences == null) {
            return ResponseEntity.notFound().build();
        }

        List<School> allSchools = repo.findAll();

        // scoring and sorting schools
        List<School> scoredSchools = allSchools.stream()
                .map(school -> {
                    int score = calculateMatchScore(school, preferences);
                    return new SchoolScore(school, score);
                })
                .filter(scored -> scored.score > 0)// this is to filter out schools that have a score of 0
                .sorted(Comparator.comparingInt((SchoolScore s) -> s.score).reversed()
                        .thenComparing(s -> s.school.getRanking() != null ? s.school.getRanking() : Integer.MAX_VALUE))
                .limit(5)
                .map(scored -> scored.school)
                .collect(Collectors.toList());

        return ResponseEntity.ok(scoredSchools);
    }

    // this is where we calculate the match score between a school and student preferences

    private int calculateMatchScore(School school, StudentPreference preferences) {
        int score = 0;

        if (preferences.getSchoolType() != null && school.getType() != null) {
            if (preferences.getSchoolType() == StudentPreference.SchoolType.BOTH) {
                score += 5; // Partial match for BOTH
            } else if (preferences.getSchoolType().name().equals(school.getType().name())) {
                score += 10; // Exact match
            }
        }

        if (preferences.getState() != null && school.getState() != null) {
            if (preferences.getState().equalsIgnoreCase(school.getState())) {
                score += 10;
            }
        }

        if (preferences.getEnrollmentType() != null && school.getEnrollmentType() != null) {
            if (preferences.getEnrollmentType().name().equals(school.getEnrollmentType().name())) {
                score += 10;
            }
        }

        if (preferences.getModality() != null && school.getModality() != null) {
            if (preferences.getModality().name().equals(school.getModality().name())) {
                score += 10;
            }
        }

        if (preferences.getRequirementType() != null && school.getRequirementType() != null) {
            if (preferences.getRequirementType().name().equals(school.getRequirementType().name())) {
                score += 10;
            }
        }

        if (preferences.getProgramType() != null && school.getProgramType() != null) {
            if (preferences.getProgramType().equalsIgnoreCase(school.getProgramType())) {
                score += 10;
            }
        }

        //// budget matching within ±$5k, closer is better
        if (preferences.getBudget() != null && school.getAnnualTuition() != null) {
            double budget = preferences.getBudget();
            double annualTuition = school.getAnnualTuition().doubleValue();
            double difference = Math.abs(annualTuition - budget);
            
            if (difference <= 5000) {
                int budgetScore = (int) (15 - (difference / 1000));
                score += Math.max(10, budgetScore); 
            }
        }

        return score;
    }

    // simple class to hold the schools
    private static class SchoolScore {
        School school;
        int score;

        SchoolScore(School school, int score) {
            this.school = school;
            this.score = score;
        }
    }


    @PostMapping("/search")
    public ResponseEntity<List<School>> searchSchools(@RequestBody Map<String, Object> searchCriteria) {
        try {
            String state = searchCriteria.containsKey("state") ? (String) searchCriteria.get("state") : null;
            String schoolTypeStr = searchCriteria.containsKey("schoolType") ? (String) searchCriteria.get("schoolType") : null;
            School.SchoolType schoolType = null;
            if (schoolTypeStr != null) {
                try {
                    schoolType = School.SchoolType.valueOf(schoolTypeStr.toUpperCase());
                } catch (IllegalArgumentException e) {}
            }
            String programType = searchCriteria.containsKey("programType") ? (String) searchCriteria.get("programType") : null;
            BigDecimal maxBudget = null;
            if (searchCriteria.containsKey("budget")) {
                Object budgetObj = searchCriteria.get("budget");
                if (budgetObj instanceof Number) {
                    maxBudget = BigDecimal.valueOf(((Number) budgetObj).doubleValue());
                }
            }
            
            List<School> schools = repo.findMatchingSchools(state, schoolType, programType, maxBudget);
            return ResponseEntity.ok(schools);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * getting details for a specific school
     * 
     * GET /api/schools/{schoolId}
     */

    @GetMapping("/{schoolId}")
    public ResponseEntity<School> getSchoolById(@PathVariable Long schoolId) {
        return repo.findById(schoolId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * getting all schools (from the db)
     * 
     * GET /api/schools
     */

    @GetMapping
    public List<School> getAllSchools() {
        return repo.findAll();
    }
}
