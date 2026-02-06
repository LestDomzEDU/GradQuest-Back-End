package com.project03.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

@Configuration
public class GithubOAuth2TokenClientConfig {

  private static final Logger log = LoggerFactory.getLogger(GithubOAuth2TokenClientConfig.class);

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

    DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();

    RestTemplate restTemplate = new RestTemplate(
        new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory())
    );

    // Keep existing converters + ensure token response converter exists
    var converters = new ArrayList<>(restTemplate.getMessageConverters());
    converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
    restTemplate.setMessageConverters(converters);

    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

    // Ask GitHub for JSON and safely log error responses
    restTemplate.getInterceptors().add((req, body, exec) -> {
      req.getHeaders().set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
      var resp = exec.execute(req, body);

      try {
        byte[] bytes = resp.getBody().readAllBytes();
        String text = new String(bytes, StandardCharsets.UTF_8);
        String lower = text.toLowerCase();

        // Never log if access_token is present
        if (!lower.contains("access_token") && (lower.contains("error") || lower.contains("bad_verification_code")
            || lower.contains("incorrect_client_credentials") || lower.contains("redirect_uri_mismatch"))) {
          String snippet = text.length() > 800 ? text.substring(0, 800) + "..." : text;
          log.error("GitHub token endpoint error payload: {}", snippet);
        }

        // replay body for downstream parsing
        return new org.springframework.http.client.ClientHttpResponse() {
          @Override public org.springframework.http.HttpStatusCode getStatusCode() throws java.io.IOException { return resp.getStatusCode(); }
          @Override public int getRawStatusCode() throws java.io.IOException { return resp.getRawStatusCode(); }
          @Override public String getStatusText() throws java.io.IOException { return resp.getStatusText(); }
          @Override public void close() { resp.close(); }
          @Override public java.io.InputStream getBody() { return new java.io.ByteArrayInputStream(bytes); }
          @Override public HttpHeaders getHeaders() { return resp.getHeaders(); }
        };
      } catch (Exception ignored) {
        return resp;
      }
    });

    delegate.setRestOperations(restTemplate);

    return (OAuth2AuthorizationCodeGrantRequest request) -> {
      OAuth2AccessTokenResponse tokenResponse = delegate.getTokenResponse(request);

      if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
        throw new OAuth2AuthorizationException(new OAuth2Error(
            "invalid_token_response",
            "GitHub did not return an access_token. Check callback URL + client secret in Heroku.",
            null
        ));
      }
      return tokenResponse;
    };
  }
}
