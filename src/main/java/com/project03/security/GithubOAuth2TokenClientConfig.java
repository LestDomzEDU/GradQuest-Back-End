package com.project03.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

@Configuration
public class GithubOAuth2TokenClientConfig {

  private static final Logger log = LoggerFactory.getLogger(GithubOAuth2TokenClientConfig.class);

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {

    DefaultAuthorizationCodeTokenResponseClient delegate = new DefaultAuthorizationCodeTokenResponseClient();

    ClientHttpRequestFactory base = new SimpleClientHttpRequestFactory();
    BufferingClientHttpRequestFactory buffering = new BufferingClientHttpRequestFactory(base);

    RestTemplate restTemplate = new RestTemplate(buffering);

    // Keep existing converters + ensure token response converter is present
    var converters = new ArrayList<>(restTemplate.getMessageConverters());
    converters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
    restTemplate.setMessageConverters(converters);

    // Handle proper OAuth2 error HTTP codes correctly
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

    // Ask GitHub for JSON and log token endpoint failures safely
    restTemplate.getInterceptors().add(acceptJson());
    restTemplate.getInterceptors().add(safeLogTokenResponses());

    delegate.setRestOperations(restTemplate);

    return (OAuth2AuthorizationCodeGrantRequest req) -> {
      try {
        OAuth2AccessTokenResponse tokenResponse = delegate.getTokenResponse(req);

        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
          OAuth2Error err = new OAuth2Error(
              "invalid_token_response",
              "GitHub did not return an access_token. Check callback URL and GITHUB_CLIENT_SECRET.",
              null
          );
          throw new OAuth2AuthorizationException(err);
        }
        return tokenResponse;

      } catch (OAuth2AuthorizationException ex) {
        // Already a clean OAuth error
        throw ex;
      } catch (IllegalArgumentException iae) {
        // This is the crash you originally saw; convert to clean OAuth error.
        log.error("GitHub token exchange failed (accessToken null). Likely bad secret or callback mismatch.", iae);
        OAuth2Error err = new OAuth2Error(
            "invalid_token_response",
            "GitHub token exchange failed: access token was null. Check callback URL and client secret.",
            null
        );
        throw new OAuth2AuthorizationException(err);
      }
    };
  }

  private static ClientHttpRequestInterceptor acceptJson() {
    return (request, body, execution) -> {
      request.getHeaders().set(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
      return execution.execute(request, body);
    };
  }

  /**
   * Logs GitHub token endpoint responses ONLY when they look like an error payload,
   * and avoids logging any access_token if present.
   */
  private static ClientHttpRequestInterceptor safeLogTokenResponses() {
    return (request, body, execution) -> {
      var response = execution.execute(request, body);

      try {
        byte[] bytes = response.getBody().readAllBytes();
        String text = new String(bytes, StandardCharsets.UTF_8);

        // Re-wrap body so downstream converters can still read it
        var wrapped = new ReplayableClientHttpResponse(response, bytes);

        // If it contains access_token, do NOT log (avoid leaking secrets)
        String lower = text.toLowerCase();
        if (lower.contains("access_token")) {
          return wrapped;
        }

        // If it looks like an oauth error, log it (truncate)
        if (lower.contains("error") || lower.contains("bad_verification_code") || lower.contains("incorrect_client_credentials")) {
          String snippet = text.length() > 600 ? text.substring(0, 600) + "..." : text;
          log.error("GitHub token endpoint response looked like an error: {}", snippet);
        }

        return wrapped;

      } catch (Exception e) {
        // If we can't read/log, just return original response
        return response;
      }
    };
  }

  /**
   * Minimal wrapper that replays a previously-read response body.
   */
  private static class ReplayableClientHttpResponse implements org.springframework.http.client.ClientHttpResponse {
    private final org.springframework.http.client.ClientHttpResponse delegate;
    private final byte[] body;

    ReplayableClientHttpResponse(org.springframework.http.client.ClientHttpResponse delegate, byte[] body) {
      this.delegate = delegate;
      this.body = body;
    }

    @Override public org.springframework.http.HttpStatusCode getStatusCode() throws IOException { return delegate.getStatusCode(); }
    @Override public int getRawStatusCode() throws IOException { return delegate.getRawStatusCode(); }
    @Override public String getStatusText() throws IOException { return delegate.getStatusText(); }
    @Override public void close() { delegate.close(); }
    @Override public java.io.InputStream getBody() { return new java.io.ByteArrayInputStream(body); }
    @Override public HttpHeaders getHeaders() { return delegate.getHeaders(); }
  }
}
