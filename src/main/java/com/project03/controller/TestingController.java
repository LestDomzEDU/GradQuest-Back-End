package com.project03.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestingController {
    @GetMapping("/")
    public String root() {
        return "API is running! Visit /api/schools to see all Schools in API.";
    }
    
    // just checking to see if 
    @GetMapping("/testing")
    public String testing() {
        return "Route is working";
    }
}