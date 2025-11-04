package com.project03.controller;

import org.springframework.web.bind.annotation.*;

/**
 * This will handle saving and retrieving student preferences/criteria that will need to be filled out
 * by tthe student during the intake form process after logining in with OAuth or going to the profile page
 */
@RestController
@RequestMapping("/api/preferences")
public class StudentPreferenceController {

    /**
     * save or update student preferences/criteria
     * 
     * POST /api/preferences
     * 
     * an example JSON:
     * {
     *   "budget": 50000,
     *   "schoolYear": "2025",
     *   "expectedGrad": "2029",
     *   "schoolType": "BOTH", // PUBLIC, PRIVATE, BOTH
     *   "state": "California",
     *   "targetCountry": "USA",
     *   "major": "Computer Science",
     *   "enrollmentType": "FULL_TIME", // PART_TIME, FULL_TIME
     *   "modality": "HYBRID", // ONLINE, IN_PERSON, HYBRID
     *   "gpa": 3.7,
     *   "capstoneRequired": true
     * }
     */

    @PostMapping
    public String savePreferences(@RequestBody String preferences) {
        // TODO: Extract student ID from authentication token
        // TODO: Save preferences to database
        return "Preferences saved";
    }

    /**
     * get current user's saved preferences
     * 
     * GET /api/preferences
     */

    @GetMapping
    public String getPreferences() {
        // TODO: Extract student ID from authentication token
        // TODO: Retrieve preferences from database
        return "User preferences";
    }

    /**
     * update student preferences
     * 
     * PUT /api/preferences
     */

    @PutMapping
    public String updatePreferences(@RequestBody String preferences) {
        // TODO: Extract student ID from authentication token
        // TODO: Update preferences in database
        return "Preferences updated";
    }

    /**
     * delete student preferences
     * DELETE /api/preferences
     */
    
    @DeleteMapping
    public String deletePreferences() {
        // TODO: Extract student ID from authentication token
        // TODO: Delete preferences from database
        return "Preferences deleted";
    }
}

