package com.project03.controller;

import com.project03.model.Reminder;
import com.project03.model.School;
import com.project03.model.User;
import com.project03.repository.ReminderRepository;
import com.project03.repository.SchoolRepository;
import com.project03.service.CurrentUserService;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller for managing deadline reminders for applications
 */
@RestController
@RequestMapping("/api/reminders")
public class ReminderController {

    private static final Logger log = LoggerFactory.getLogger(ReminderController.class);

    private final ReminderRepository reminderRepo;
    private final CurrentUserService currentUser;
    private final SchoolRepository schoolRepo;

    public ReminderController(ReminderRepository reminderRepo,
                             CurrentUserService currentUser,
                             SchoolRepository schoolRepo) {
        this.reminderRepo = reminderRepo;
        this.currentUser = currentUser;
        this.schoolRepo = schoolRepo;
    }

    /**
     * Create a reminder for a school's application deadline
     * 
     * POST /api/reminders?schoolId={schoolId}
     * 
     * Creates a reminder 1 week before the school's application deadline
     */
    @PostMapping
    public ResponseEntity<?> createReminder(Authentication authentication,
                                            @RequestParam Long schoolId) {
        User user = currentUser.require(authentication);
        try {

            // Get school
            School school = schoolRepo.findById(schoolId).orElse(null);
            if (school == null) {
                return ResponseEntity.notFound().build();
            }

            // Check if reminder already exists for this user and school
            List<Reminder> existing = reminderRepo.findByUserAndSchoolId(user, schoolId);
            if (!existing.isEmpty()) {
                // Return existing reminder instead of creating duplicate
                return ResponseEntity.ok(existing.get(0));
            }

            // Parse application deadline from school
            String deadlineStr = school.getApplicationDeadline();
            if (deadlineStr == null || deadlineStr.trim().isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "School does not have an application deadline");
                return ResponseEntity.badRequest().body(error);
            }

            LocalDate deadlineDate;
            try {
                // Try parsing as ISO date (YYYY-MM-DD)
                deadlineDate = LocalDate.parse(deadlineStr.trim());
            } catch (DateTimeParseException e) {
                // Try other common formats if needed
                Map<String, String> error = new HashMap<>();
                error.put("error", "Invalid date format for application deadline: " + deadlineStr);
                return ResponseEntity.badRequest().body(error);
            }

            // Use the deadline date as the reminder date
            LocalDate reminderDate = deadlineDate;

            // Create reminder
            Reminder reminder = new Reminder();
            reminder.setUser(user);
            reminder.setSchool(school);
            reminder.setReminderDate(reminderDate);
            reminder.setTitle("Application deadline: " + school.getName());
            reminder.setDescription("Submit application for " + school.getName() + 
                                   (school.getProgramName() != null ? " - " + school.getProgramName() : ""));
            reminder.setReminderType(Reminder.ReminderType.DEADLINE);
            reminder.setIsCompleted(false);

            Reminder savedReminder = reminderRepo.save(reminder);
            return ResponseEntity.ok(savedReminder);
        } catch (Exception e) {
            log.warn("Request failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to create reminder");
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * getting all the reminders for the logged-in student
     * 
     * GET /api/reminders
     */
    @GetMapping
    public ResponseEntity<List<Reminder>> getUserReminders(Authentication authentication) {
        User user = currentUser.require(authentication);
        List<Reminder> reminders = reminderRepo.findByUser(user);
        return ResponseEntity.ok(reminders);
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
     * delete a reminder by reminder ID
     * 
     * DELETE /api/reminders/{reminderId}
     */
    @DeleteMapping("/{reminderId}")
    public ResponseEntity<?> deleteReminder(@PathVariable Long reminderId, Authentication authentication) {
        User user = currentUser.require(authentication);
        try {

            Reminder reminder = reminderRepo.findByIdAndUser(reminderId, user)
                    .orElse(null);
            if (reminder == null) {
                return ResponseEntity.notFound().build();
            }

            reminderRepo.delete(reminder);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.warn("Request failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to delete reminder");
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * Delete reminder by school ID (when user unsaves a school)
     * 
     * DELETE /api/reminders/school/{schoolId}
     */
    @DeleteMapping("/school/{schoolId}")
    public ResponseEntity<?> deleteReminderBySchool(@PathVariable Long schoolId, Authentication authentication) {
        User user = currentUser.require(authentication);
        try {

            List<Reminder> reminders = reminderRepo.findByUserAndSchoolId(user, schoolId);
            if (reminders.isEmpty()) {
                return ResponseEntity.notFound().build();
            }

            // Delete all reminders for this school and user
            reminderRepo.deleteAll(reminders);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.warn("Request failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to delete reminder");
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * toggle a reminder's completed status
     * 
     * PATCH /api/reminders/{reminderId}/complete
     *
     */
    @PatchMapping("/{reminderId}/complete")
    public ResponseEntity<?> toggleReminderComplete(@PathVariable Long reminderId, Authentication authentication) {
        User user = currentUser.require(authentication);
        try {

            Reminder reminder = reminderRepo.findByIdAndUser(reminderId, user)
                    .orElse(null);
            if (reminder == null) {
                return ResponseEntity.notFound().build();
            }

            // Toggle the completed status
            reminder.setIsCompleted(!reminder.getIsCompleted());
            Reminder updatedReminder = reminderRepo.save(reminder);
            return ResponseEntity.ok(updatedReminder);
        } catch (Exception e) {
            log.warn("Request failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to toggle reminder completion status");
            return ResponseEntity.badRequest().body(error);
        }
    }
}

