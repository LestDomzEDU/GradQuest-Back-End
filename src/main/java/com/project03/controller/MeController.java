package com.project03.controller;

import com.project03.model.User;
import com.project03.service.OAuthUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class MeController {

  private final OAuthUserService oauthUserService;

  @Autowired
  public MeController(OAuthUserService oauthUserService) {
    this.oauthUserService = oauthUserService;
  }

  @GetMapping("/api/me")
  public Map<String, Object> me(@AuthenticationPrincipal OAuth2User oauth2User, Authentication authentication) {
    if (oauth2User == null) {
      return Map.of("authenticated", false);
    }

    // Determine the OAuth provider from the authentication token
    String registrationId = null;
    if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
      registrationId = oauthToken.getAuthorizedClientRegistrationId();
    }
    
    // Fallback: detect provider from attributes if registrationId is not available
    if (registrationId == null || registrationId.isEmpty()) {
      registrationId = oauthUserService.detectProvider(oauth2User);
    }

    // Get or create the User entity from OAuth2User
    User user;
    try {
      user = oauthUserService.getOrCreateUser(oauth2User, registrationId);
    } catch (Exception e) {
      // If user creation fails, still return OAuth info but log the error
      // This allows the frontend to still work even if DB operations fail
      Map<String, Object> attrs = oauth2User.getAttributes();
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("authenticated", true);
      out.put("error", "Failed to create/update user: " + e.getMessage());
      
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
      String name = ghName != null ? ghName : ggName;
      String avatar = ghAvatar != null ? ghAvatar : ggPicture;
      
      out.put("login", login);
      out.put("name", name);
      out.put("email", ggEmail);
      out.put("avatar_url", avatar);
      return out;
    }

    Map<String, Object> attrs = oauth2User.getAttributes();
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("authenticated", true);
    
    // Include the user ID - this is what other parts of the app need
    out.put("userId", user.getId());
    out.put("id", user.getId()); // Alias for convenience
    
    // GitHub fields
    String ghLogin = (String) attrs.get("login");
    String ghAvatar = (String) attrs.get("avatar_url");
    String ghName = (String) attrs.get("name");

    // Google OIDC fields
    String ggEmail = (String) attrs.get("email");
    String ggName = (String) attrs.get("name");
    String ggPicture = (String) attrs.get("picture");

    // normalized (use database values as primary, fallback to OAuth attributes)
    String login = ghLogin != null ? ghLogin : (ggEmail != null ? ggEmail : user.getEmail());
    String name = user.getName() != null ? user.getName() : (ghName != null ? ghName : ggName);
    String email = user.getEmail() != null ? user.getEmail() : ggEmail;
    String avatar = user.getAvatarUrl() != null ? user.getAvatarUrl() : (ghAvatar != null ? ghAvatar : ggPicture);

    out.put("login", login);
    out.put("name", name);
    out.put("email", email);
    out.put("avatar_url", avatar);
    // Note: oauthProvider is stored in DB but not exposed - it's an implementation detail
    out.put("attributes", attrs);
    
    return out;
  }
}
