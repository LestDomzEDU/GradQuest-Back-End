package com.project03.model;

import jakarta.persistence.*;
import java.time.LocalDate;

/**
 * representing a student's application to a school.
 * nd links a student to a school from their top 5 matches.
 * will go over this later again to make sure we have all needed fields that we
 * talked about in class
 */
@Entity
@Table(name = "applications")
public class Application {
    /* hello */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "school_id", nullable = false)
    private School school;

    // program name for this application
    @Column(name = "program_name")
    private String programName;

    // application deadline for this program
    @Column(name = "application_deadline")
    private LocalDate applicationDeadline;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private ApplicationStatus status;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "submission_date")
    private LocalDate submissionDate;

    @Column(name = "decision_date")
    private LocalDate decisionDate;

    // SIMPLE CONSTRUCTORS, GETTERS, AND SETTERS

    public Application() {
        this.status = ApplicationStatus.PENDING;
    }

    public Application(User user, School school, String programName) {
        this.user = user;
        this.school = school;
        this.programName = programName;
        this.status = ApplicationStatus.PENDING;
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

    public School getSchool() {
        return school;
    }

    public void setSchool(School school) {
        this.school = school;
    }

    public String getProgramName() {
        return programName;
    }

    public void setProgramName(String programName) {
        this.programName = programName;
    }

    public LocalDate getApplicationDeadline() {
        return applicationDeadline;
    }

    public void setApplicationDeadline(LocalDate applicationDeadline) {
        this.applicationDeadline = applicationDeadline;
    }

    public ApplicationStatus getStatus() {
        return status;
    }

    public void setStatus(ApplicationStatus status) {
        this.status = status;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public LocalDate getSubmissionDate() {
        return submissionDate;
    }

    public void setSubmissionDate(LocalDate submissionDate) {
        this.submissionDate = submissionDate;
    }

    public LocalDate getDecisionDate() {
        return decisionDate;
    }

    public void setDecisionDate(LocalDate decisionDate) {
        this.decisionDate = decisionDate;
    }

    /**
     * Enum for application status
     */
    public enum ApplicationStatus {
        PENDING,
        SUBMITTED,
        ACCEPTED,
        REJECTED
    }
}
