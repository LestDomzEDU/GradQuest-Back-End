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
    if (user == null) return Map.of("authenticated", false);

    Map<String, Object> attrs = user.getAttributes();
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("authenticated", true);

    // GitHub fields
    String ghLogin = (String) attrs.get("login");
    String ghAvatar = (String) attrs.get("avatar_url");
    String ghName = (String) attrs.get("name");

    // Google OIDC fields
    String ggEmail = (String) attrs.get("email");
    String ggName = (String) attrs.get("name");
    String ggPicture = (String) attrs.get("picture");

    // normalized
    String login = ghLogin != null ? ghLogin : ggEmail;
    String name  = ghName  != null ? ghName  : ggName;
    String avatar = ghAvatar != null ? ghAvatar : ggPicture;

    out.put("login", login);
    out.put("name", name);
    out.put("email", ggEmail);
    out.put("avatar_url", avatar);
    out.put("attributes", attrs);
    return out;
  }
}
