package com.project03.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.ArrayList;
import java.util.List;

/**
 * Registers OAuth providers (GitHub required; Google/Discord optional).
 *
 * Uses environment variables on Heroku:
 *  - GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
 */
@Configuration
public class OAuthClientRegistrationConfig {

  private static final Logger log = LoggerFactory.getLogger(OAuthClientRegistrationConfig.class);

  @Value("${oauth.redirect-base:http://localhost:8082}")
  private String redirectBase;

  // GitHub (required)
  @Value("${github.client-id:}")
  private String githubClientIdProp;

  @Value("${github.client-secret:}")
  private String githubClientSecretProp;

  // Google (optional)
  @Value("${google.client-id:}")
  private String googleClientIdProp;

  @Value("${google.client-secret:}")
  private String googleClientSecretProp;

  // Discord (optional)
  @Value("${discord.client-id:}")
  private String discordClientIdProp;

  @Value("${discord.client-secret:}")
  private String discordClientSecretProp;

  private static String n(String v) { return v == null ? "" : v.trim(); }

  private static String firstNonBlank(String a, String b) {
    a = n(a);
    if (!a.isBlank()) return a;
    b = n(b);
    if (!b.isBlank()) return b;
    return "";
  }

  private static String normalizeBase(String base) {
    base = n(base);
    if (base.isBlank()) base = "http://localhost:8082";
    if (!base.startsWith("http://") && !base.startsWith("https://")) base = "http://" + base;
    while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
    return base;
  }

  private boolean hasText(String s) {
    return s != null && !s.trim().isEmpty();
  }

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    String base = normalizeBase(redirectBase);

    // ---- GitHub (required) ----
    String ghClientId = firstNonBlank(githubClientIdProp, System.getenv("GITHUB_CLIENT_ID"));
    String ghClientSecret = firstNonBlank(githubClientSecretProp, System.getenv("GITHUB_CLIENT_SECRET"));

    if (ghClientId.isBlank() || ghClientSecret.isBlank()) {
      throw new IllegalStateException(
          "Missing GitHub OAuth credentials. Set github.client-id/github.client-secret (local) " +
              "or set GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET (Heroku)."
      );
    }

    String githubRedirect = base + "/login/oauth2/code/github";

    // ✅ IMPORTANT: Use CLIENT_SECRET_POST for GitHub (most reliable)
    ClientRegistration github = ClientRegistration.withRegistrationId("github")
        .clientId(ghClientId)
        .clientSecret(ghClientSecret)
        .clientName("GitHub")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .redirectUri(githubRedirect)
        .scope("read:user", "user:email")
        .authorizationUri("https://github.com/login/oauth/authorize")
        .tokenUri("https://github.com/login/oauth/access_token")
        .userInfoUri("https://api.github.com/user")
        .userNameAttributeName("id")
        .build();

    List<ClientRegistration> regs = new ArrayList<>();
    regs.add(github);

    // ---- Google (optional) ----
    String gClientId = firstNonBlank(googleClientIdProp, System.getenv("GOOGLE_CLIENT_ID"));
    String gClientSecret = firstNonBlank(googleClientSecretProp, System.getenv("GOOGLE_CLIENT_SECRET"));

    if (!gClientId.isBlank() && !gClientSecret.isBlank()) {
      String googleRedirect = base + "/login/oauth2/code/google";
      ClientRegistration google = CommonOAuth2Provider.GOOGLE.getBuilder("google")
          .clientId(gClientId)
          .clientSecret(gClientSecret)
          .redirectUri(googleRedirect)
          .build();
      regs.add(google);
    } else {
      log.info("Google OAuth credentials not set; Google login will be unavailable.");
    }

    // ---- Discord (optional) ----
    String dClientId = firstNonBlank(discordClientIdProp, System.getenv("DISCORD_CLIENT_ID"));
    String dClientSecret = firstNonBlank(discordClientSecretProp, System.getenv("DISCORD_CLIENT_SECRET"));

    if (!dClientId.isBlank() && !dClientSecret.isBlank()) {
      String discordRedirect = base + "/login/oauth2/code/discord";
      ClientRegistration discord = ClientRegistration
          .withRegistrationId("discord")
          .clientId(dClientId)
          .clientSecret(dClientSecret)
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri(discordRedirect)
          .scope("identify", "email")
          .authorizationUri("https://discord.com/api/oauth2/authorize")
          .tokenUri("https://discord.com/api/oauth2/token")
          .userInfoUri("https://discord.com/api/users/@me")
          .userNameAttributeName("id")
          .clientName("Discord")
          .build();
      regs.add(discord);
    } else {
      log.info("Discord OAuth credentials not set; Discord login will be unavailable.");
    }

    log.info("OAuth redirect base={}", base);
    log.info("OAuth registrations={}", regs.stream().map(ClientRegistration::getRegistrationId).toList());

    return new InMemoryClientRegistrationRepository(regs);
  }
}
