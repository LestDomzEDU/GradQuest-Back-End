package com.project03.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class OAuthClientRegistrationConfig {

  @Value("${oauth.redirect-base:http://localhost:8081}")
  private String redirectBase;

  @Value("${GITHUB_CLIENT_ID:}")
  private String githubClientId;

  @Value("${GITHUB_CLIENT_SECRET:}")
  private String githubClientSecret;

  @Value("${DISCORD_CLIENT_ID:}")
  private String discordClientId;

  @Value("${DISCORD_CLIENT_SECRET:}")
  private String discordClientSecret;

  private boolean hasText(String s) {
    return s != null && !s.trim().isEmpty();
  }

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    List<ClientRegistration> regs = new ArrayList<>();

    // ---- GitHub (only register if configured) ----
    if (hasText(githubClientId) && hasText(githubClientSecret)) {
      ClientRegistration github = ClientRegistration
          .withRegistrationId("github")
          .clientId(githubClientId.trim())
          .clientSecret(githubClientSecret.trim())
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

      regs.add(github);
    } else {
      System.out.println("[OAuth] GitHub OAuth not configured (missing GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET).");
    }

    // ---- Discord (only register if configured) ----
    if (hasText(discordClientId) && hasText(discordClientSecret)) {
      ClientRegistration discord = ClientRegistration
          .withRegistrationId("discord")
          .clientId(discordClientId.trim())
          .clientSecret(discordClientSecret.trim())
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri(redirectBase + "/login/oauth2/code/{registrationId}")
          .scope("identify", "email")
          .authorizationUri("https://discord.com/api/oauth2/authorize")
          .tokenUri("https://discord.com/api/oauth2/token")
          .userInfoUri("https://discord.com/api/users/@me")
          .userNameAttributeName("id")
          .clientName("Discord")
          .build();

      regs.add(discord);
    } else {
      System.out.println("[OAuth] Discord OAuth not configured (missing DISCORD_CLIENT_ID / DISCORD_CLIENT_SECRET).");
    }

    return new InMemoryClientRegistrationRepository(regs);
  }
}
