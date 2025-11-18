package com.project03.repository;

import com.project03.model.Reminder;
import com.project03.model.User;
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
     * Find all reminders for a specific user
     */
    List<Reminder> findByUser(User user);
    
    /**
     * Find reminders by application ID
     */
    List<Reminder> findByApplicationId(Long applicationId);
    
    /**
     * Find reminders for a user and application
     */
    List<Reminder> findByUserAndApplicationId(User user, Long applicationId);
    
    /**
     * Find a specific reminder by ID and user (for security)
     */
    Optional<Reminder> findByIdAndUser(Long id, User user);
    
    /**
     * Find upcoming reminders within a date range
     */
    @Query("SELECT r FROM Reminder r WHERE r.user.id = :userId AND " +
           "r.isCompleted = false AND " +
           "r.reminderDate >= CURRENT_DATE AND " +
           "r.reminderDate <= :endDate " +
           "ORDER BY r.reminderDate ASC, r.reminderTime ASC")
    List<Reminder> findUpcomingReminders(@Param("userId") Long userId, 
                                        @Param("endDate") LocalDate endDate);
    
    /**
     * Find reminders by completion status
     */
    List<Reminder> findByUserAndIsCompleted(User user, Boolean isCompleted);
    
    /**
     * Find reminders by type
     */
    List<Reminder> findByUserAndReminderType(User user, Reminder.ReminderType reminderType);
    
    /**
     * Find overdue reminders (past date and not completed)
     */
    @Query("SELECT r FROM Reminder r WHERE r.user.id = :userId AND " +
           "r.isCompleted = false AND " +
           "r.reminderDate < CURRENT_DATE " +
           "ORDER BY r.reminderDate ASC")
    List<Reminder> findOverdueReminders(@Param("userId") Long userId);
    
    /**
     * Count reminders by user
     */
    long countByUser(User user);
    
    /**
     * Count incomplete reminders for a user
     */
    long countByUserAndIsCompleted(User user, Boolean isCompleted);
}

