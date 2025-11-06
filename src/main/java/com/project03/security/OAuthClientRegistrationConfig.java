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

  // You can still override these via env vars if you want
  @Value("${GITHUB_CLIENT_ID:Ov23liNJm44d2aLDyANl}")
  private String clientId;

  @Value("${GITHUB_CLIENT_SECRET:55ec6302d52239aa1af39af8e16e57f7fb3dbbcb}")
  private String clientSecret;

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    ClientRegistration github = ClientRegistration
        .withRegistrationId("github")
        .clientId(clientId)
        .clientSecret(clientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("read:user", "user:email")
        .authorizationUri("https://github.com/login/oauth/authorize")
        .tokenUri("https://github.com/login/oauth/access_token")
        .userInfoUri("https://api.github.com/user")
        .userNameAttributeName("id")
        .clientName("GitHub")
        .build();

    return new InMemoryClientRegistrationRepository(github);
  }
}
