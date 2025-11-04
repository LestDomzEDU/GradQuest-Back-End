package com.project03.controller;

import org.springframework.web.bind.annotation.*;

/**
 * Controller for managing deadline reminders for applications
 * I am not totally sure how we are going to implement this feature yet
 * but this is a starting point that may or may not work with what we hav in mind
 */
@RestController
@RequestMapping("/api/reminders")
public class ReminderController {

    /**
     * generate the reminders for the logged-in student
     * need to find a way to get them from the school 
     * not completely sure how we are going to do this yet
     * 
     * POST /api/reminders
     * 
     * this would be the expected body JSON format:
     * {
     *   "applicationId": 456,
     *   "reminderDate": "2025-11-15",
     *   "reminderTime": "09:00",
     *   "title": "Application deadline approaching",
     *   "description": "Submit application for University X",
     *   "reminderType": "DEADLINE" // DEADLINE, FOLLOW_UP, PERSONAL_STATEMENT, REFERENCES, CUSTOM
     * }
     */

    @PostMapping
    public String createReminder(@RequestBody String reminderData) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify application belongs to student
        // TODO: Save reminder to database
        return "Reminder created";
    }

    /**
     * getting all the reminders for the logged-in student
     * 
     * GET /api/reminders
     */

    @GetMapping
    public String getUserReminders() {
        // TODO: Extract student ID from authentication token
        // TODO: Retrieve all reminders for this student
        return "User reminders";
    }

    /**
     * get reminders for a specific application incase we need this
     * 
     * GET /api/reminders/application/{applicationId}
     */

    @GetMapping("/application/{applicationId}")
    public String getRemindersByApplication(@PathVariable Long applicationId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify application belongs to student
        // TODO: Retrieve reminders for this application
        return "Reminders for application ID: " + applicationId;
    }

    /**
     * get upcoming reminders (ex., within next 2 weeks or less)
     * 
     * GET /api/reminders/upcoming
     */

    @GetMapping("/upcoming")
    public String getUpcomingReminders(
            @RequestParam(required = false, defaultValue = "7") Integer days
    ) {
        // TODO: Extract student ID from authentication token
        // TODO: Calculate date range (today + days)
        // TODO: Retrieve reminders within date range
        return "Upcoming reminders for next " + days + " days";
    }

    /**
     * get a specific reminder by ID
     
     * GET /api/reminders/{reminderId}
     */

    @GetMapping("/{reminderId}")
    public String getReminderById(@PathVariable Long reminderId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify reminder belongs to student
        // TODO: Retrieve reminder details
        return "Reminder details for ID: " + reminderId;
    }

    /**
     * update a reminder
     * 
     * PUT /api/reminders/{reminderId}
     */

    @PutMapping("/{reminderId}")
    public String updateReminder(@PathVariable Long reminderId, @RequestBody String reminderData) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify reminder belongs to student
        // TODO: Update reminder in database
        return "Reminder updated";
    }

    /**
     * delete a reminder we may not need anymore
     * 
     * DELETE /api/reminders/{reminderId}
     */
    @DeleteMapping("/{reminderId}")
    public String deleteReminder(@PathVariable Long reminderId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify reminder belongs to student
        // TODO: Delete reminder from database
        return "Reminder deleted";
    }

    /**
     * mark a reminder as completed/dismissed
     * 
     * PATCH /api/reminders/{reminderId}/complete
     *
     */
    @PatchMapping("/{reminderId}/complete")
    public String markReminderComplete(@PathVariable Long reminderId) {
        // TODO: Extract student ID from authentication token
        // TODO: Verify reminder belongs to student
        // TODO: Mark reminder as completed in database
        return "Reminder marked as complete";
    }
}

