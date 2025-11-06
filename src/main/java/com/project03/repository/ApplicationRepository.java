package com.project03.repository;

import com.project03.model.Application;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

/**
 * im not 100 percent sure what we can use this for so far but will look into it futher next week
 */
@Repository
public interface ApplicationRepository extends JpaRepository<Application, Long> {
    
    /**
     * Find all applications for a specific student
     */
    List<Application> findByStudentId(String studentId);
    
    /**
     * Find applications by student ID and status
     */
    List<Application> findByStudentIdAndStatus(String studentId, Application.ApplicationStatus status);
    
    /**
     * Find a specific application by ID and student ID (for security)
     */
    Optional<Application> findByIdAndStudentId(Long id, String studentId);
    
    /**
     * Check if an application exists for a student and school
     */
    boolean existsByStudentIdAndSchoolId(String studentId, Long schoolId);
    
    /**
     * Find applications by school ID
     */
    List<Application> findBySchoolId(Long schoolId);
    
    /**
     * Count applications by student ID
     */
    long countByStudentId(String studentId);
    
    /**
     * Count applications by status for a student
     */
    long countByStudentIdAndStatus(String studentId, Application.ApplicationStatus status);
    
    /**
     * Find applications that have upcoming deadlines within the specified number of days
     * Note: This method accepts an endDate parameter to avoid database-specific date arithmetic
     */
    @Query("SELECT a FROM Application a WHERE a.studentId = :studentId AND " +
           "a.applicationDeadline >= CURRENT_DATE AND " +
           "a.applicationDeadline <= :endDate ORDER BY a.applicationDeadline ASC")
    List<Application> findUpcomingDeadlines(@Param("studentId") String studentId, 
                                           @Param("endDate") LocalDate endDate);
}

