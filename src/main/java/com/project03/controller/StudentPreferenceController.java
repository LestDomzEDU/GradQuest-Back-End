package com.project03.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import com.project03.model.StudentPreference;
import com.project03.model.User;
import com.project03.repository.StudentPreferenceRepository;
import com.project03.repository.UserRepository;

import java.util.HashMap;
import java.util.Map;

/**
 * This will handle saving and retrieving student preferences/criteria that will need to be filled out
 * by tthe student during the intake form process after logining in with OAuth or going to the profile page
 */
@RestController
@RequestMapping("/api/preferences")
public class StudentPreferenceController {

    private final StudentPreferenceRepository repo;
    private final UserRepository userRepo;

    public StudentPreferenceController(StudentPreferenceRepository repo, UserRepository userRepo) {
        this.repo = repo;
        this.userRepo = userRepo;
    }

    @PostMapping
    public ResponseEntity<?> savePreferences(@RequestParam Long userId, @RequestBody StudentPreference preferenceDetails) {
        try {
            User user = userRepo.findById(userId).orElse(null);
            if (user == null) {
                return ResponseEntity.notFound().build();
            }
            
            StudentPreference preference = repo.findByUser(user)
                    .map(existing -> {
                        // Update existing preferences
                        if (preferenceDetails.getBudget() != null) existing.setBudget(preferenceDetails.getBudget());
                        if (preferenceDetails.getSchoolYear() != null) existing.setSchoolYear(preferenceDetails.getSchoolYear());
                        if (preferenceDetails.getExpectedGrad() != null) existing.setExpectedGrad(preferenceDetails.getExpectedGrad());
                        if (preferenceDetails.getSchoolType() != null) existing.setSchoolType(preferenceDetails.getSchoolType());
                        if (preferenceDetails.getState() != null) existing.setState(preferenceDetails.getState());
                        if (preferenceDetails.getProgramType() != null) existing.setProgramType(preferenceDetails.getProgramType());
                        if (preferenceDetails.getTargetCountry() != null) existing.setTargetCountry(preferenceDetails.getTargetCountry());
                        if (preferenceDetails.getMajor() != null) existing.setMajor(preferenceDetails.getMajor());
                        if (preferenceDetails.getEnrollmentType() != null) existing.setEnrollmentType(preferenceDetails.getEnrollmentType());
                        if (preferenceDetails.getModality() != null) existing.setModality(preferenceDetails.getModality());
                        if (preferenceDetails.getGpa() != null) existing.setGpa(preferenceDetails.getGpa());
                        if (preferenceDetails.getRequirementType() != null) existing.setRequirementType(preferenceDetails.getRequirementType());
                        return existing;
                    })
                    .orElseGet(() -> {
                        // Create new preferences
                        preferenceDetails.setUser(user);
                        return preferenceDetails;
                    });
            
            StudentPreference savedPreference = repo.save(preference);
            return ResponseEntity.ok(savedPreference);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to save preferences");
            errorResponse.put("message", e.getMessage());
            if (e.getCause() != null) {
                errorResponse.put("cause", e.getCause().getMessage());
            }
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * get current user's saved preferences
     * 
     * GET /api/preferences?userId=123
     */

    @GetMapping
    public ResponseEntity<StudentPreference> getPreferences(@RequestParam Long userId) {
        User user = userRepo.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return repo.findByUser(user)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * update student preferences
     * 
     * PUT /api/preferences?userId=123
     */

    @PutMapping
    public ResponseEntity<StudentPreference> updatePreferences(@RequestParam Long userId, @RequestBody StudentPreference preferenceDetails) {
        User user = userRepo.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return repo.findByUser(user)
                .map(preference -> {
                    if (preferenceDetails.getBudget() != null) preference.setBudget(preferenceDetails.getBudget());
                    if (preferenceDetails.getSchoolYear() != null) preference.setSchoolYear(preferenceDetails.getSchoolYear());
                    if (preferenceDetails.getExpectedGrad() != null) preference.setExpectedGrad(preferenceDetails.getExpectedGrad());
                    if (preferenceDetails.getSchoolType() != null) preference.setSchoolType(preferenceDetails.getSchoolType());
                    if (preferenceDetails.getState() != null) preference.setState(preferenceDetails.getState());
                    if (preferenceDetails.getProgramType() != null) preference.setProgramType(preferenceDetails.getProgramType());
                    if (preferenceDetails.getTargetCountry() != null) preference.setTargetCountry(preferenceDetails.getTargetCountry());
                    if (preferenceDetails.getMajor() != null) preference.setMajor(preferenceDetails.getMajor());
                    if (preferenceDetails.getEnrollmentType() != null) preference.setEnrollmentType(preferenceDetails.getEnrollmentType());
                    if (preferenceDetails.getModality() != null) preference.setModality(preferenceDetails.getModality());
                    if (preferenceDetails.getGpa() != null) preference.setGpa(preferenceDetails.getGpa());
                    if (preferenceDetails.getRequirementType() != null) preference.setRequirementType(preferenceDetails.getRequirementType());
                    StudentPreference updatedPreference = repo.save(preference);
                    return ResponseEntity.ok(updatedPreference);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * delete student preferences (basic user flow)
     * 
     * DELETE /api/preferences?userId=123
     */
    
    @DeleteMapping
    public ResponseEntity<Void> deletePreferences(@RequestParam Long userId) {
        User user = userRepo.findById(userId).orElse(null);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        if (repo.existsByUser(user)) {
            repo.deleteByUser(user);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}

