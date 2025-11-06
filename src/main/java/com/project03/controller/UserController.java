package com.project03.controller;

import com.project03.model.User;
import com.project03.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Simple UserController for testing purposes.
 * Provides endpoints to create users and get student IDs.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    /**
     * Create a user
     * 
     * POST /api/users
     * 
     * Example JSON body:
     * {
     *   "email": "test@example.com",
     *   "name": "Test User"
     * }
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String name = request.getOrDefault("name", "");

        if (email == null || email.isEmpty()) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Email is required"));
        }

        // Check if user already exists
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            Map<String, Object> response = new HashMap<>();
            response.put("message", "User already exists");
            response.put("userId", user.getId());
            response.put("studentId", String.valueOf(user.getId()));
            response.put("email", user.getEmail());
            response.put("name", user.getName());
            return ResponseEntity.ok(response);
        }

        // Create a new user
        User user = new User(email, name);
        user = userRepository.save(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", "User created successfully");
        response.put("userId", user.getId());
        response.put("studentId", String.valueOf(user.getId()));
        response.put("email", user.getEmail());
        response.put("name", user.getName());

        return ResponseEntity.ok(response);
    }

    /**
     * Get student ID by user ID
     * 
     * GET /api/users/{userId}/student-id
     */
    @GetMapping("/{userId}/student-id")
    public ResponseEntity<Map<String, Object>> getStudentIdByUserId(@PathVariable Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();
        return ResponseEntity.ok(Map.of(
            "studentId", String.valueOf(user.getId()),
            "userId", user.getId(),
            "email", user.getEmail(),
            "name", user.getName() != null ? user.getName() : ""
        ));
    }

    /**
     * List all users (for testing)
     * 
     * GET /api/users
     */
    @GetMapping
    public ResponseEntity<List<Map<String, Object>>> getAllUsers() {
        List<User> users = userRepository.findAll();
        
        List<Map<String, Object>> userList = users.stream()
            .map(user -> {
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("userId", user.getId());
                userMap.put("studentId", String.valueOf(user.getId()));
                userMap.put("email", user.getEmail());
                userMap.put("name", user.getName());
                return userMap;
            })
            .collect(Collectors.toList());

        return ResponseEntity.ok(userList);
    }

    /**
     * Get user by ID
     * 
     * GET /api/users/{userId}
     */
    @GetMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> getUserById(@PathVariable Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();
        Map<String, Object> response = new HashMap<>();
        response.put("userId", user.getId());
        response.put("studentId", String.valueOf(user.getId()));
        response.put("email", user.getEmail());
        response.put("name", user.getName());

        return ResponseEntity.ok(response);
    }
}
