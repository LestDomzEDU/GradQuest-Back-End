package com.project03.controller;

import org.springframework.web.bind.annotation.*;

/**
 * controller for school matching functionality that will be neeeded for the student intake form
 * we can handel retrieving schools based on student criteria and returning top 5 matches here
 */

@RestController
@RequestMapping("/api/schools")
public class SchoolController {

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

    /**
     * searching schools with custom criteria (alternative to using saved preferences)
     * I put this in here incase we want to allow students to do custom searches outside of their saved preferences
     * we most likely won't need this if we are only using saved preferences to get matches
     * 
     * POST /api/schools/search
     * 
     * an example JSON search can be the following: 
     * {
     *   "budget": 50000,
     *   "schoolType": "public",
     *   "state": "California",
     *   "programType": "masters"
     * }
     */

    @PostMapping("/search")
    public String searchSchools(@RequestBody String searchCriteria) {
        // TODO: Parse search criteria
        // TODO: Query schools database with filters
        // TODO: Return matching schools
        return "Search results";
    }

    /**
     * getting details for a specific school
     * 
     * GET /api/schools/{schoolId}
     */

    @GetMapping("/{schoolId}")
    public String getSchoolById(@PathVariable Long schoolId) {
        // TODO: Retrieve school details by ID
        return "School details for ID: " + schoolId;
    }

    /**
     * getting all schools (from the db)
     * 
     * GET /api/schools
     */

    @GetMapping
    public String getAllSchools(
            @RequestParam(required = false) Integer page,
            @RequestParam(required = false) Integer size
    ) {
        // TODO: Implement pagination
        // TODO: Return all schools (may need admin authentication)
        return "All schools";
    }

    /**
     * We talked about having an admin panel to manage schools and add them, we scrapped the idea but it is here incase
     * we want to implement it later
     * 
     * endpoint: ability to add a new school/program to the database
     * 
     * POST /api/schools
     */

    @PostMapping
    public String createSchool(@RequestBody String schoolData) {
        // TODO: Validate admin authentication
        // TODO: Parse school data (name, type, state, programs, costs, etc.)
        // TODO: Save school to database
        return "School created";
    }

    /**
     * another admin endpoiint that can change the information of a school
     * 
     * PUT /api/schools/{schoolId}
     */

    @PutMapping("/{schoolId}")
    public String updateSchool(@PathVariable Long schoolId, @RequestBody String schoolData) {
        // TODO: Validate admin authentication
        // TODO: Update school in database
        return "School updated";
    }

    /**
     * another admin endpoint that can delete a school
     * 
     * DELETE /api/schools/{schoolId}
     */

    @DeleteMapping("/{schoolId}")
    public String deleteSchool(@PathVariable Long schoolId) {
        // TODO: Validate admin authentication
        // TODO: Delete school from database
        return "School deleted";
    }
}

