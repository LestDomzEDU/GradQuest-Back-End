package com.project03.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.LocalDate;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ReminderJsonTest {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    @DisplayName("Reminder JSON includes the saved school's id, name, program and website")
    void exposesSchoolFields() throws Exception {
        School school = new School("UC San Diego", School.SchoolType.PUBLIC, "CA", "MS Computer Science");
        school.setId(42L);
        school.setWebsiteUrl("https://ucsd.edu");

        User user = new User();
        Reminder reminder = new Reminder(user, school, LocalDate.of(2026, 12, 1),
                "Application deadline: UC San Diego", Reminder.ReminderType.DEADLINE);

        JsonNode json = mapper.readTree(mapper.writeValueAsString(reminder));

        assertThat(json.get("schoolId").asLong()).isEqualTo(42L);
        assertThat(json.get("schoolName").asText()).isEqualTo("UC San Diego");
        assertThat(json.get("programName").asText()).isEqualTo("MS Computer Science");
        assertThat(json.get("websiteUrl").asText()).isEqualTo("https://ucsd.edu");
        assertThat(json.has("school")).isFalse();
        assertThat(json.has("user")).isFalse();
    }

    @Test
    @DisplayName("Reminder JSON has null school fields when there is no school")
    void nullSchoolFieldsWithoutSchool() throws Exception {
        Reminder reminder = new Reminder();
        reminder.setTitle("Custom");
        reminder.setReminderDate(LocalDate.of(2026, 12, 1));
        reminder.setReminderType(Reminder.ReminderType.CUSTOM);

        JsonNode json = mapper.readTree(mapper.writeValueAsString(reminder));

        assertThat(json.get("schoolId").isNull()).isTrue();
        assertThat(json.get("schoolName").isNull()).isTrue();
    }
}
