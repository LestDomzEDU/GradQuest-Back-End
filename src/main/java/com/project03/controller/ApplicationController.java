package com.project03.controller;

import org.springframework.web.bind.annotation.*;

/**
 * Controller for managing student applications to schools.
 * Handles saving applications from the top 5 matched schools.
 */
@RestController
@RequestMapping("/api/applications")
public class ApplicationController {

    /**
     * save a new application for the logged-in student
     * 
     * POST /api/applications
     * 
     * this would be the expected JSON payload:
     * {
     *   "schoolId": 123,
     *   "schoolName": "University Name",
     *   "programName": "Masters in Computer Science",
     *   "applicationDeadline": "2025-12-01",
     *   "status": "pending" // "pending", "submitted", "accepted", "rejected"
     * }
     */

    @PostMapping
    public String createApplication(@RequestBody String applicationData) {
        // TODO: Extract student ID from authentication token
        // TODO: Validate school exists
        // TODO: Save application to database
        return "Application saved";
    }

    /**
     * getting all applications for the logged-in student
     *
     * GET /api/applications
     */

    @GetMapping
    public String getUserApplications() {
        // TODO: Extract student ID from authentication token
        // TODO: Retrieve all applications for this student
        return "User applications";
    }

    /**
     * getting a specific application by ID
     * 
     * GET /api/applications/{applicationId}
     */

    @GetMapping("/{applicationId}")
    public String getApplicationById(@PathVariable Long applicationId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify application belongs to student (security check)
        // TODO: Retrieve application details
        return "Application details for ID: " + applicationId;
    }

    /**
     * if we need to update an application
     * 
     * PUT /api/applications/{applicationId}
     */

    @PutMapping("/{applicationId}")
    public String updateApplication(@PathVariable Long applicationId, @RequestBody String applicationData) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify application belongs to student
        // TODO: Update application in database
        return "Application updated";
    }

    /**
     * delete if user don't want to apply anymore or keep track of it? 
     * 
     * DELETE /api/applications/{applicationId}
     */

    @DeleteMapping("/{applicationId}")
    public String deleteApplication(@PathVariable Long applicationId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify application belongs to student
        // TODO: Delete application from database
        return "Application deleted";
    }

    /**
     * we can try to filter applications by status? 
     * not sure if this is something we want to implement right now
     * 
     * GET /api/applications?status=pending
     */

    @GetMapping(params = "status")
    public String getApplicationsByStatus(@RequestParam String status) {
        // TODO: Extract student ID from authentication token
        // TODO: Filter applications by status
        return "Applications with status: " + status;
    }
}

