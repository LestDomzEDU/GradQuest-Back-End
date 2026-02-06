package com.project03.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;

import java.util.List;

/**
 * GitHub token endpoint: request JSON response via Accept header.
 *
 * IMPORTANT: Do NOT intercept+consume+rewrap the response body. That can break parsing.
 */
@Configuration
public class GithubOAuth2TokenClientConfig {

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

    DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

    // RestTemplate with the converters Spring Security expects
    RestTemplate restTemplate = new RestTemplate(List.of(
        new FormHttpMessageConverter(),
        new OAuth2AccessTokenResponseHttpMessageConverter(),
        new MappingJackson2HttpMessageConverter()
    ));

    client.setRestOperations(restTemplate);

    // Add Accept: application/json to the token request
    OAuth2AuthorizationCodeGrantRequestEntityConverter entityConverter =
        new OAuth2AuthorizationCodeGrantRequestEntityConverter();

    client.setRequestEntityConverter(req -> {
      var entity = entityConverter.convert(req);
      if (entity == null) return null;

      HttpHeaders headers = new HttpHeaders();
      headers.putAll(entity.getHeaders());
      headers.set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);

      MultiValueMap<String, String> body = entity.getBody();
      return new org.springframework.http.RequestEntity<>(
          body,
          headers,
          entity.getMethod(),
          entity.getUrl()
      );
    });

    return request -> {
      OAuth2AccessTokenResponse token = client.getTokenResponse(request);
      // If token exchange failed, Spring will throw before we get here.
      return token;
    };
  }
}
