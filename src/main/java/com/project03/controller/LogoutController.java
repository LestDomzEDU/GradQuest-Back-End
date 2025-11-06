package com.project03.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class LogoutController {

  @PostMapping("/api/logout")
  public Map<String, Object> logout(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
    if (auth != null) {
      new SecurityContextLogoutHandler().logout(request, response, auth);
    }
    return Map.of("logout", true);
  }
}
