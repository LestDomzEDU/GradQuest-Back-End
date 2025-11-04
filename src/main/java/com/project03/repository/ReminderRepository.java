package com.project03.repository;

import com.project03.model.Reminder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Reminder entity.
 */
@Repository
public interface ReminderRepository extends JpaRepository<Reminder, Long> {
    
    /**
     * Find all reminders for a specific student
     */
    List<Reminder> findByStudentId(String studentId);
    
    /**
     * Find reminders by application ID
     */
    List<Reminder> findByApplicationId(Long applicationId);
    
    /**
     * Find reminders for a student and application
     */
    List<Reminder> findByStudentIdAndApplicationId(String studentId, Long applicationId);
    
    /**
     * Find a specific reminder by ID and student ID (for security)
     */
    Optional<Reminder> findByIdAndStudentId(Long id, String studentId);
    
    /**
     * Find upcoming reminders within a date range
     */
    @Query("SELECT r FROM Reminder r WHERE r.studentId = :studentId AND " +
           "r.isCompleted = false AND " +
           "r.reminderDate >= CURRENT_DATE AND " +
           "r.reminderDate <= :endDate " +
           "ORDER BY r.reminderDate ASC, r.reminderTime ASC")
    List<Reminder> findUpcomingReminders(@Param("studentId") String studentId, 
                                        @Param("endDate") LocalDate endDate);
    
    /**
     * Find reminders by completion status
     */
    List<Reminder> findByStudentIdAndIsCompleted(String studentId, Boolean isCompleted);
    
    /**
     * Find reminders by type
     */
    List<Reminder> findByStudentIdAndReminderType(String studentId, Reminder.ReminderType reminderType);
    
    /**
     * Find overdue reminders (past date and not completed)
     */
    @Query("SELECT r FROM Reminder r WHERE r.studentId = :studentId AND " +
           "r.isCompleted = false AND " +
           "r.reminderDate < CURRENT_DATE " +
           "ORDER BY r.reminderDate ASC")
    List<Reminder> findOverdueReminders(@Param("studentId") String studentId);
    
    /**
     * Count reminders by student ID
     */
    long countByStudentId(String studentId);
    
    /**
     * Count incomplete reminders for a student
     */
    long countByStudentIdAndIsCompleted(String studentId, Boolean isCompleted);
}

