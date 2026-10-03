package com.project03.controller;

import com.project03.model.User;
import com.project03.service.OAuthUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * One-click login for local development, so testing doesn't require a GitHub OAuth app.
 * Only exists when the "dev" Spring profile is active (./gradlew bootRun); never in prod.
 *
 * POST /dev/login?as=tester  -> logs in as test user "tester" (created on first use)
 */
@RestController
@Profile("dev")
public class DevLoginController {

  private final OAuthUserService oauthUserService;
  private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

  public DevLoginController(OAuthUserService oauthUserService) {
    this.oauthUserService = oauthUserService;
  }

  @PostMapping("/dev/login")
  public Map<String, Object> login(@RequestParam(defaultValue = "tester") String as,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
    String handle = as.trim().toLowerCase().replaceAll("[^a-z0-9_-]", "");
    if (handle.isEmpty()) handle = "tester";

    Map<String, Object> attributes = Map.of(
        "id", "dev-" + handle,
        "login", handle,
        "name", "Dev " + handle,
        "email", handle + "@dev.local"
    );
    OAuth2User principal = new DefaultOAuth2User(
        List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "id");

    User user = oauthUserService.getOrCreateUser(principal, "dev");

    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(new OAuth2AuthenticationToken(principal, principal.getAuthorities(), "dev"));
    SecurityContextHolder.setContext(context);
    securityContextRepository.saveContext(context, request, response);

    return Map.of("authenticated", true, "userId", user.getId(), "login", handle);
  }
}
