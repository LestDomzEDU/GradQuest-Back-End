package com.project03.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class MeController {

  @GetMapping("/api/me")
  public Map<String, Object> me(@AuthenticationPrincipal OAuth2User user) {
    if (user == null) {
      return Map.of("authenticated", false);
    }
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("authenticated", true);
    out.put("name", user.getAttribute("name"));
    out.put("login", user.getAttribute("login"));
    out.put("id", user.getAttribute("id"));
    out.put("avatar_url", user.getAttribute("avatar_url"));
    out.put("attributes", user.getAttributes());
    return out;
  }
}
