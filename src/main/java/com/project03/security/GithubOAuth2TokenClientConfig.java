package com.project03.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

@Configuration
public class GithubOAuth2TokenClientConfig {

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

    // Start with a normal RestTemplate so it has the default converters (including FormHttpMessageConverter)
    RestTemplate restTemplate = new RestTemplate();

    // Ensure Spring Security can parse OAuth2AccessTokenResponse properly
    restTemplate.getMessageConverters().add(new OAuth2AccessTokenResponseHttpMessageConverter());

    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

    // Ask GitHub for JSON (still works if it returns form-urlencoded)
    restTemplate.getInterceptors().add((request, body, execution) -> {
      request.getHeaders().set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
      return execution.execute(request, body);
    });

    client.setRestOperations(restTemplate);
    return client;
  }
}
