package com.project03.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Entity representing student search preferences/criteria from the form submission.
 * Each student can have one set of preferences (one-to-one with studentId).
 */
@Entity
@Table(name = "student_preferences")
public class StudentPreference {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String studentId;

    @Column(nullable = false)
    private Double budget;

    @Column(name = "school_year", nullable = false)
    private String schoolYear;

    @Column(name = "expected_grad", nullable = false)
    private String expectedGrad;

    @Column(name = "school_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private SchoolType schoolType;

    @Column(nullable = false)
    private String state;

    @Column(name = "program_type")
    private String programType;

    @Column(name = "target_country")
    private String targetCountry;

    @Column
    private String major;

    @Column(name = "enrollment_type")
    @Enumerated(EnumType.STRING)
    private EnrollmentType enrollmentType; // PART_TIME or FULL_TIME

    @Column
    @Enumerated(EnumType.STRING)
    private Modality modality; // ONLINE, IN_PERSON, HYBRID

    @Column
    private Double gpa;

    @Column(name = "capstone_required")
    private Boolean capstoneRequired;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Constructors
    public StudentPreference() {
    }

    public StudentPreference(String studentId, Double budget, String schoolYear, 
                           String expectedGrad, SchoolType schoolType, String state) {
        this.studentId = studentId;
        this.budget = budget;
        this.schoolYear = schoolYear;
        this.expectedGrad = expectedGrad;
        this.schoolType = schoolType;
        this.state = state;
    }

    // Lifecycle callbacks
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getStudentId() {
        return studentId;
    }

    public void setStudentId(String studentId) {
        this.studentId = studentId;
    }

    public Double getBudget() {
        return budget;
    }

    public void setBudget(Double budget) {
        this.budget = budget;
    }

    public String getSchoolYear() {
        return schoolYear;
    }

    public void setSchoolYear(String schoolYear) {
        this.schoolYear = schoolYear;
    }

    public String getExpectedGrad() {
        return expectedGrad;
    }

    public void setExpectedGrad(String expectedGrad) {
        this.expectedGrad = expectedGrad;
    }

    public SchoolType getSchoolType() {
        return schoolType;
    }

    public void setSchoolType(SchoolType schoolType) {
        this.schoolType = schoolType;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getProgramType() {
        return programType;
    }

    public void setProgramType(String programType) {
        this.programType = programType;
    }

    public String getTargetCountry() {
        return targetCountry;
    }

    public void setTargetCountry(String targetCountry) {
        this.targetCountry = targetCountry;
    }

    public String getMajor() {
        return major;
    }

    public void setMajor(String major) {
        this.major = major;
    }

    public EnrollmentType getEnrollmentType() {
        return enrollmentType;
    }

    public void setEnrollmentType(EnrollmentType enrollmentType) {
        this.enrollmentType = enrollmentType;
    }

    public Modality getModality() {
        return modality;
    }

    public void setModality(Modality modality) {
        this.modality = modality;
    }

    public Double getGpa() {
        return gpa;
    }

    public void setGpa(Double gpa) {
        this.gpa = gpa;
    }

    public Boolean getCapstoneRequired() {
        return capstoneRequired;
    }

    public void setCapstoneRequired(Boolean capstoneRequired) {
        this.capstoneRequired = capstoneRequired;
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
     * Enum for school type preference
     */
    public enum SchoolType {
        PUBLIC,
        PRIVATE,
        BOTH
    }

    /**
     * Enum for enrollment type preference
     */
    public enum EnrollmentType {
        PART_TIME,
        FULL_TIME
    }

    /**
     * Enum for learning modality preference
     */
    public enum Modality {
        ONLINE,
        IN_PERSON,
        HYBRID
    }
}

