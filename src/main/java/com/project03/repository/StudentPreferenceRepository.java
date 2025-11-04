package com.project03.repository;

import com.project03.model.StudentPreference;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for StudentPreference entity.
 */
@Repository
public interface StudentPreferenceRepository extends JpaRepository<StudentPreference, Long> {
    
    /**
     * Find preferences by student ID
     * Each student should have only one set of preferences
     */
    Optional<StudentPreference> findByStudentId(String studentId);
    
    /**
     * Check if preferences exist for a student
     */
    boolean existsByStudentId(String studentId);
    
    /**
     * Delete preferences by student ID
     */
    void deleteByStudentId(String studentId);
}

