package com.project03.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

/**
 * IMPORTANT:
 * Do NOT include exception messages in redirect URLs.
 * Tomcat will 400 if the URL contains illegal characters.
 *
 * We log the detailed error to Heroku logs, and redirect to a stable URL.
 */
public class OAuthFailureHandler extends SimpleUrlAuthenticationFailureHandler {

  private static final Logger log = LoggerFactory.getLogger(OAuthFailureHandler.class);

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request,
      HttpServletResponse response,
      AuthenticationException exception
  ) throws IOException, ServletException {

    // Full detail stays in logs (safe)
    log.error("OAuth login failed: {}", exception.getMessage(), exception);

    // Redirect to a clean URL (never 400)
    getRedirectStrategy().sendRedirect(request, response, "/?login=failed");
  }
}
