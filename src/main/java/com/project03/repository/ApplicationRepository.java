package com.project03.repository;

import com.project03.model.Application;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface ApplicationRepository extends JpaRepository<Application, Long> {

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
