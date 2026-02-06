package com.project03.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;

@Configuration
public class GithubOAuth2TokenClientConfig {

  private static final Logger log = LoggerFactory.getLogger(GithubOAuth2TokenClientConfig.class);

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

    // Delegate to Spring's default token client, but harden it for GitHub "200 + error json" cases.
    DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();

    // Start from default converters
    RestTemplate restTemplate = new RestTemplate();

    // Ensure the OAuth2 token response converter is present (handles JSON token responses)
    // Keep existing converters too (form, string, etc.)
    var converters = new ArrayList<>(restTemplate.getMessageConverters());
    converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
    restTemplate.setMessageConverters(converters);

    // Treat proper OAuth2 error HTTP responses correctly
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

    // Ask GitHub for JSON (GitHub supports this)
    restTemplate.getInterceptors().add((request, body, execution) -> {
      request.getHeaders().set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
      return execution.execute(request, body);
    });

    delegate.setRestOperations(restTemplate);

    // Wrap the delegate to detect "missing access_token"
    return (OAuth2AuthorizationCodeGrantRequest request) -> {
      try {
        OAuth2AccessTokenResponse tokenResponse = delegate.getTokenResponse(request);

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
          // This happens when GitHub returns JSON like:
          // {"error":"bad_verification_code","error_description":"..."} (often HTTP 200)
          OAuth2Error err = new OAuth2Error(
              "invalid_token_response",
              "GitHub did not return an access_token. " +
                  "Most common causes: wrong GITHUB_CLIENT_SECRET, reused/expired code, or callback URL mismatch.",
              null
          );
          throw new OAuth2AuthorizationException(err);
        }

        return tokenResponse;

      } catch (IllegalArgumentException iae) {
        // Convert the crash you are seeing into a clean OAuth2 error
        log.error("GitHub token exchange failed (accessToken null). Check GitHub client secret and callback URL.", iae);
        OAuth2Error err = new OAuth2Error(
            "invalid_token_response",
            "GitHub token exchange failed: access token was null. " +
                "Check GITHUB_CLIENT_SECRET and GitHub OAuth callback URL.",
            null
        );
        throw new OAuth2AuthorizationException(err);
      }
    };
  }
}
