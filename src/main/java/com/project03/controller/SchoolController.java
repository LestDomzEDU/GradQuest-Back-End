package com.project03.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.project03.model.School;
import com.project03.repository.SchoolRepository;

import java.util.HashMap;
import java.util.Map;
import java.math.BigDecimal;
import java.util.List;

/**
 * controller for school matching functionality that will be neeeded for the student intake form
 * we can handel retrieving schools based on student criteria and returning top 5 matches here
 */

@RestController
@RequestMapping("/api/schools")
public class SchoolController {

    private final SchoolRepository repo;

    public SchoolController(SchoolRepository repo) {
        this.repo = repo;
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
    public String getTop5Schools() {
        // TODO: Extract student ID from authentication token
        // TODO: Retrieve student preferences
        // TODO(orithm): Match schools against preferences (budget, state, school type, etc.)
        // TODO: Return top 5 matching schools sorted by relevance
        return "Top 5 matching schools";
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

    /**
     * 
     * endpoint: ability to add a new school/program to the database
     * 
     * POST /api/schools
     */

     @PostMapping
     public ResponseEntity<?> createSchool(@RequestBody School school) {
         try {
             School savedSchool = repo.save(school);
             return ResponseEntity.ok(savedSchool);
         } catch (Exception e) {
             Map<String, String> errorResponse = new HashMap<>();
             errorResponse.put("error", "Failed to create school");
             errorResponse.put("message", e.getMessage());
             if (e.getCause() != null) {
                 errorResponse.put("cause", e.getCause().getMessage());
             }
             return ResponseEntity.badRequest().body(errorResponse);
         }
     }

    /**
     * another admin endpoiint that can change the information of a school
     * 
     * PUT /api/schools/{schoolId}
     */

    @PutMapping("/{schoolId}")
    public ResponseEntity<School> updateSchool(@PathVariable Long schoolId, @RequestBody School schoolDetails) {
        return repo.findById(schoolId)
                .map(school -> {
                    if (schoolDetails.getName() != null) school.setName(schoolDetails.getName());
                    if (schoolDetails.getType() != null) school.setType(schoolDetails.getType());
                    if (schoolDetails.getState() != null) school.setState(schoolDetails.getState());
                    if (schoolDetails.getCity() != null) school.setCity(schoolDetails.getCity());
                    if (schoolDetails.getProgramName() != null) school.setProgramName(schoolDetails.getProgramName());
                    if (schoolDetails.getProgramType() != null) school.setProgramType(schoolDetails.getProgramType());
                    if (schoolDetails.getAnnualTuition() != null) school.setAnnualTuition(schoolDetails.getAnnualTuition());
                    if (schoolDetails.getTotalCost() != null) school.setTotalCost(schoolDetails.getTotalCost());
                    if (schoolDetails.getApplicationDeadline() != null) school.setApplicationDeadline(schoolDetails.getApplicationDeadline());
                    if (schoolDetails.getApplicationFee() != null) school.setApplicationFee(schoolDetails.getApplicationFee());
                    if (schoolDetails.getDescription() != null) school.setDescription(schoolDetails.getDescription());
                    if (schoolDetails.getWebsiteUrl() != null) school.setWebsiteUrl(schoolDetails.getWebsiteUrl());
                    if (schoolDetails.getRanking() != null) school.setRanking(schoolDetails.getRanking());
                    if (schoolDetails.getAccreditation() != null) school.setAccreditation(schoolDetails.getAccreditation());
                    if (schoolDetails.getEnrollmentType() != null) school.setEnrollmentType(schoolDetails.getEnrollmentType());
                    if (schoolDetails.getModality() != null) school.setModality(schoolDetails.getModality());
                    if (schoolDetails.getRequirementType() != null) school.setRequirementType(schoolDetails.getRequirementType());
                    School updatedSchool = repo.save(school);
                    return ResponseEntity.ok(updatedSchool);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * another admin endpoint that can delete a school
     * 
     * DELETE /api/schools/{schoolId}
     */

    @DeleteMapping("/{schoolId}")
    public ResponseEntity<Void> deleteSchool(@PathVariable Long schoolId) {
        
        if (repo.existsById(schoolId)) {
            repo.deleteById(schoolId);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}

