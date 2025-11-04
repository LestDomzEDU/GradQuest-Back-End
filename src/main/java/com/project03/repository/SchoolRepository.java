package com.project03.repository;

import com.project03.model.School;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.util.List;

/**
 * Repository interface for School entity.
 */
@Repository
public interface SchoolRepository extends JpaRepository<School, Long> {
    
    /**
     * Find schools by state
     */
    List<School> findByState(String state);
    
    /**
     * Find schools by type (PUBLIC or PRIVATE)
     */
    List<School> findByType(School.SchoolType type);
    
    /**
     * Find schools by state and type
     */
    List<School> findByStateAndType(String state, School.SchoolType type);
    
    /**
     * Find schools by master program type
     */
    List<School> findByProgramType(String programType);
    
    /**
     * Find schools where annual tuition is less than or equal to budget that the student has chosen
     */
    List<School> findByAnnualTuitionLessThanEqual(BigDecimal budget);
    
    /**
     * find the school that matches the most with the criteria that the student has chosen via the student intake form
     * 
     * below is the query that we can use
     * I havent tested it yet but this is an example of what we can do to find the schools that match the most with the criteria
     */
    @Query("SELECT s FROM School s WHERE " +
           "(:state IS NULL OR s.state = :state) AND " +
           "(:schoolType IS NULL OR s.type = :schoolType) AND " +
           "(:programType IS NULL OR s.programType = :programType) AND " +
           "(:maxBudget IS NULL OR s.annualTuition <= :maxBudget) " +
           "ORDER BY s.ranking ASC NULLS LAST, s.annualTuition ASC")
    List<School> findMatchingSchools(
            @Param("state") String state,
            @Param("schoolType") School.SchoolType schoolType,
            @Param("programType") String programType,
            @Param("maxBudget") BigDecimal maxBudget
    );
    
    /**
     * To find schools by the name
     */
    List<School> findByNameContainingIgnoreCase(String name);
    
    /**
     * Get all school
     */
    Page<School> findAll(Pageable pageable);
    
    /**
     * Find schools by multiple states
     */
    List<School> findByStateIn(List<String> states);
}

