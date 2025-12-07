package com.project03.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Entity
@Table(name = "reminders")
public class Reminder {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "application_id", nullable = true)
    @JsonIgnore
    private Application application;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "school_id", nullable = true)
    @JsonIgnore
    private School school;

    // date for the reminder
    @Column(name = "reminder_date", nullable = false)
    private LocalDate reminderDate; 

    // Optional time for the reminder
    @Column(name = "reminder_time")
    private LocalTime reminderTime; 

    // Reminder title
    @Column(nullable = false)
    private String title; 

    // Reminder description/details
    @Column(columnDefinition = "TEXT")
    private String description;
    
    // Reminder type
    @Column(name = "reminder_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private ReminderType reminderType;

    // Whether reminder has been completed/dismissed
    @Column(name = "is_completed", nullable = false)
    private Boolean isCompleted; 

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // SIMPLE CONSTRUCTORS, GETTERS, AND SETTERS

    public Reminder() {
        this.isCompleted = false;
    }

    public Reminder(User user, Application application, LocalDate reminderDate, 
                   String title, ReminderType reminderType) {
        this.user = user;
        this.application = application;
        this.reminderDate = reminderDate;
        this.title = title;
        this.reminderType = reminderType;
        this.isCompleted = false;
    }

    public Reminder(User user, School school, LocalDate reminderDate, 
                   String title, ReminderType reminderType) {
        this.user = user;
        this.school = school;
        this.reminderDate = reminderDate;
        this.title = title;
        this.reminderType = reminderType;
        this.isCompleted = false;
    }

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Application getApplication() {
        return application;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    public School getSchool() {
        return school;
    }

    public void setSchool(School school) {
        this.school = school;
    }

    public LocalDate getReminderDate() {
        return reminderDate;
    }

    public void setReminderDate(LocalDate reminderDate) {
        this.reminderDate = reminderDate;
    }

    public LocalTime getReminderTime() {
        return reminderTime;
    }

    public void setReminderTime(LocalTime reminderTime) {
        this.reminderTime = reminderTime;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public ReminderType getReminderType() {
        return reminderType;
    }

    public void setReminderType(ReminderType reminderType) {
        this.reminderType = reminderType;
    }

    public Boolean getIsCompleted() {
        return isCompleted;
    }

    public void setIsCompleted(Boolean isCompleted) {
        this.isCompleted = isCompleted;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Enum for reminder type
     */
    public enum ReminderType {
        DEADLINE,
        FOLLOW_UP,
        PERSONAL_STATEMENT,
        REFERENCES,
        CUSTOM
    }
}

