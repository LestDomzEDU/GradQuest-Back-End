package com.project03.repository;

import com.project03.model.StudentPreference;
import com.project03.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for StudentPreference entity.
 */
@Repository
public interface StudentPreferenceRepository extends JpaRepository<StudentPreference, Long> {
    
    /**
     * Find preferences by user
     * Each user should have only one set of preferences
     */
    Optional<StudentPreference> findByUser(User user);
    
    /**
     * Check if preferences exist for a user
     */
    boolean existsByUser(User user);
    
    /**
     * Delete preferences by user
     */
    void deleteByUser(User user);
}

