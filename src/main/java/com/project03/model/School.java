package com.project03.model;

import jakarta.persistence.*;
import java.math.BigDecimal;

/**
 * this will be used to represent the schools that are in our database that are going to be given to the students
 * based on their preferences and criteria that they chose while filling out the form after logging in
 */

@Entity
@Table(name = "schools")
public class School {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private SchoolType type;

    @Column(nullable = false)
    private String state;

    @Column(name = "city")
    private String city;

    @Column(name = "program_name")
    private String programName;

    @Column(name = "program_type")
    private String programType;

    @Column(name = "annual_tuition", precision = 10, scale = 2)
    private BigDecimal annualTuition;

    @Column(name = "total_cost", precision = 10, scale = 2)
    private BigDecimal totalCost;

    @Column(name = "application_deadline")
    private String applicationDeadline;

    @Column(name = "application_fee", precision = 10, scale = 2)
    private BigDecimal applicationFee;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "website_url")
    private String websiteUrl;

    @Column(name = "ranking")
    private Integer ranking;

    @Column(name = "accreditation")
    private String accreditation;

    @Column(name = "enrollment_type")
    @Enumerated(EnumType.STRING)
    private EnrollmentType enrollmentType; // PART_TIME or FULL_TIME

    @Column
    @Enumerated(EnumType.STRING)
    private Modality modality; // ONLINE, IN_PERSON, HYBRID

    @Column(name = "requirement_type")
    @Enumerated(EnumType.STRING)
    private RequirementType requirementType; // CAPSTONE, GRE, NEITHER, BOTH

    // Constructors
    public School() {
    }

    public School(String name, SchoolType type, String state, String programName) {
        this.name = name;
        this.type = type;
        this.state = state;
        this.programName = programName;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public SchoolType getType() {
        return type;
    }

    public void setType(SchoolType type) {
        this.type = type;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getProgramName() {
        return programName;
    }

    public void setProgramName(String programName) {
        this.programName = programName;
    }

    public String getProgramType() {
        return programType;
    }

    public void setProgramType(String programType) {
        this.programType = programType;
    }

    public BigDecimal getAnnualTuition() {
        return annualTuition;
    }

    public void setAnnualTuition(BigDecimal annualTuition) {
        this.annualTuition = annualTuition;
    }

    public BigDecimal getTotalCost() {
        return totalCost;
    }

    public void setTotalCost(BigDecimal totalCost) {
        this.totalCost = totalCost;
    }

    public String getApplicationDeadline() {
        return applicationDeadline;
    }

    public void setApplicationDeadline(String applicationDeadline) {
        this.applicationDeadline = applicationDeadline;
    }

    public BigDecimal getApplicationFee() {
        return applicationFee;
    }

    public void setApplicationFee(BigDecimal applicationFee) {
        this.applicationFee = applicationFee;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getWebsiteUrl() {
        return websiteUrl;
    }

    public void setWebsiteUrl(String websiteUrl) {
        this.websiteUrl = websiteUrl;
    }

    public Integer getRanking() {
        return ranking;
    }

    public void setRanking(Integer ranking) {
        this.ranking = ranking;
    }

    public String getAccreditation() {
        return accreditation;
    }

    public void setAccreditation(String accreditation) {
        this.accreditation = accreditation;
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

    public RequirementType getRequirementType() {
        return requirementType;
    }

    public void setRequirementType(RequirementType requirementType) {
        this.requirementType = requirementType;
    }

    /**
     * Enum for school type
     */
    public enum SchoolType {
        PUBLIC,
        PRIVATE
    }

    /**
     * Enum for enrollment type
     */
    public enum EnrollmentType {
        PART_TIME,
        FULL_TIME
    }

    /**
     * Enum for learning modality
     */
    public enum Modality {
        ONLINE,
        IN_PERSON,
        HYBRID
    }

    /**
     * Enum for requirement type (capstone, GRE, neither, or both)
     */
    public enum RequirementType {
        CAPSTONE,
        GRE,
        NEITHER,
        BOTH
    }
}

