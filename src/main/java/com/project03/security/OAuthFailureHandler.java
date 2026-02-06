package com.project03.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

public class OAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {

  private static final Logger log = LoggerFactory.getLogger(OAuthFailureHandler.class);

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException exception
  ) throws IOException, ServletException {

    // Log it
    log.error("OAuth login failed: {}", exception.getMessage(), exception);

    // Send reason back to browser (safe: no tokens)
    String url = UriComponentsBuilder
        .fromPath("/")
        .queryParam("login", "failed")
        .queryParam("reason", sanitize(exception.getMessage()))
        .build()
        .toUriString();

    getRedirectStrategy().sendRedirect(request, response, url);
  }

  private String sanitize(String msg) {
    if (msg == null) return "unknown";
    // Avoid huge querystrings
    msg = msg.replaceAll("[\\r\\n\\t]", " ");
    if (msg.length() > 180) msg = msg.substring(0, 180);
    return msg;
  }
}
