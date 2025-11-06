package com.project03.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class OAuthClientRegistrationConfig {

  // Use localhost. For Android emulator, run: adb reverse tcp:8080 tcp:8080
  @Value("${OAUTH_REDIRECT_BASE:http://localhost:8080}")
  private String redirectBase;

  // GitHub (unchanged)
  @Value("${GITHUB_CLIENT_ID:Ov23liNJm44d2aLDyANl}")
  private String githubClientId;

  @Value("${GITHUB_CLIENT_SECRET:55ec6302d52239aa1af39af8e16e57f7fb3dbbcb}")
  private String githubClientSecret;

  // Google (your real IDs provided; swap to env vars before shipping)
  @Value("${GOOGLE_CLIENT_ID:70728075111-153fojf0ehe0as72nv344ir1jhuqfpk8.apps.googleusercontent.com}")
  private String googleClientId;

  @Value("${GOOGLE_CLIENT_SECRET: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}")
  private String googleClientSecret;

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    ClientRegistration github = ClientRegistration
        .withRegistrationId("github")
        .clientId(githubClientId)
        .clientSecret(githubClientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(redirectBase + "/login/oauth2/code/{registrationId}")
        .scope("read:user", "user:email")
        .authorizationUri("https://github.com/login/oauth/authorize")
        .tokenUri("https://github.com/login/oauth/access_token")
        .userInfoUri("https://api.github.com/user")
        .userNameAttributeName("id")
        .clientName("GitHub")
        .build();

ClientRegistration google = ClientRegistration
    .withRegistrationId("google")
    .clientId(googleClientId)
    .clientSecret(googleClientSecret)
    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .redirectUri(redirectBase + "/login/oauth2/code/{registrationId}")
    .scope("openid", "profile", "email")
    .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
    .tokenUri("https://oauth2.googleapis.com/token")
    .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")   // <-- add this
    .userInfoUri("https://openidconnect.googleapis.com/v1/userinfo")
    .userNameAttributeName("sub")
    .clientName("Google")
    .build();

    return new InMemoryClientRegistrationRepository(github, google);
  }
}
