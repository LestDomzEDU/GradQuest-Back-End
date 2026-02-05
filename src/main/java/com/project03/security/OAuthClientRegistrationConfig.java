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

@Configuration
public class OAuthClientRegistrationConfig {

<<<<<<< Updated upstream
  // IMPORTANT:
  // This should point at your deployed backend base URL in prod.
  // It defaults to your Heroku app, but you can override locally with
  // OAUTH_REDIRECT_BASE=http://localhost:8080 for local testing.
  @Value("${OAUTH_REDIRECT_BASE:https://grad-quest-app-2cac63f2b9b2.herokuapp.com}")
  private String redirectBase;

  // GitHub OAuth (unchanged)
  @Value("${GITHUB_CLIENT_ID:}")
  private String githubClientId;
=======
  private static final Logger log = LoggerFactory.getLogger(OAuthClientRegistrationConfig.class);

  @Value("${oauth.redirect-base:http://localhost:8082}")
  private String redirectBase;

  // GitHub
  @Value("${github.client-id:}")
  private String githubClientIdProp;
>>>>>>> Stashed changes

  @Value("${github.client-secret:}")
  private String githubClientSecretProp;

<<<<<<< Updated upstream
  // Discord OAuth (new)
  @Value("${DISCORD_CLIENT_ID:}")
  private String discordClientId;
=======
  // Google (you said do NOT remove)
  @Value("${google.client-id:}")
  private String googleClientIdProp;
>>>>>>> Stashed changes

  @Value("${google.client-secret:}")
  private String googleClientSecretProp;

<<<<<<< Updated upstream
  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    // ---- GitHub registration ----
    ClientRegistration github = ClientRegistration
        .withRegistrationId("github")
        .clientId(githubClientId)
        .clientSecret(githubClientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        // Spring’s default login callback: {baseUrl}/login/oauth2/code/{registrationId}
        .redirectUri(redirectBase + "/login/oauth2/code/{registrationId}")
=======
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

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    String base = normalizeBase(redirectBase);

    // Prefer properties (dev secrets). Fallback to env vars only if missing.
    String ghClientId = firstNonBlank(githubClientIdProp, System.getenv("GITHUB_CLIENT_ID"));
    String ghClientSecret = firstNonBlank(githubClientSecretProp, System.getenv("GITHUB_CLIENT_SECRET"));

    if (ghClientId.isBlank() || ghClientSecret.isBlank()) {
      throw new IllegalStateException(
          "Missing GitHub OAuth credentials. Set github.client-id and github.client-secret (dev secrets) or env vars."
      );
    }

    String githubRedirect = base + "/login/oauth2/code/github";

    ClientRegistration github = ClientRegistration.withRegistrationId("github")
        .clientId(ghClientId)
        .clientSecret(ghClientSecret)
        .clientName("GitHub")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .redirectUri(githubRedirect)
>>>>>>> Stashed changes
        .scope("read:user", "user:email")
        .authorizationUri("https://github.com/login/oauth/authorize")
        .tokenUri("https://github.com/login/oauth/access_token")
        .userInfoUri("https://api.github.com/user")
        .userNameAttributeName("id")
<<<<<<< Updated upstream
        .clientName("GitHub")
        .build();

    // ---- Discord registration (replaces Google) ----
    ClientRegistration discord = ClientRegistration
        .withRegistrationId("discord")
        .clientId(discordClientId)
        .clientSecret(discordClientSecret)
        // Discord expects client_id / client_secret in the POST body
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        // MUST match the redirect you configure in the Discord Developer Portal
        // Example: https://grad-quest-app-2cac63f2b9b2.herokuapp.com/login/oauth2/code/discord
        .redirectUri(redirectBase + "/login/oauth2/code/{registrationId}")
        .scope("identify", "email")
        .authorizationUri("https://discord.com/api/oauth2/authorize")
        .tokenUri("https://discord.com/api/oauth2/token")
        .userInfoUri("https://discord.com/api/users/@me")
        .userNameAttributeName("id")
        .clientName("Discord")
        .build();

    // We now support two providers: github and discord
    return new InMemoryClientRegistrationRepository(github, discord);
=======
        .build();

    List<ClientRegistration> regs = new ArrayList<>();
    regs.add(github);

    // Google registration (optional at runtime; link can exist, but login works only if creds are set)
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
      log.warn("Google login link is present, but google.client-id / google.client-secret are missing. Google login will fail until set.");
    }

    // Helpful sanity logs (NO secrets)
    log.info("OAuth redirect base={}", base);
    log.info("GitHub redirectUri={}", githubRedirect);
    log.info("Registrations={}", regs.stream().map(ClientRegistration::getRegistrationId).toList());

    return new InMemoryClientRegistrationRepository(regs);
>>>>>>> Stashed changes
  }
}
