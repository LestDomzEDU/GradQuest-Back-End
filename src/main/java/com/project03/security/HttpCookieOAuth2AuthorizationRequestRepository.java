package com.project03.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;

import java.util.Base64;

public class HttpCookieOAuth2AuthorizationRequestRepository
    implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final String OAUTH2_AUTH_REQUEST_COOKIE_NAME = "oauth2_auth_request";
  private static final int COOKIE_EXPIRE_SECONDS = 180;

  @Override
  public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
    return CookieUtils.getCookie(request, OAUTH2_AUTH_REQUEST_COOKIE_NAME)
        .map(c -> deserialize(c.getValue()))
        .orElse(null);
  }

  @Override
  public void saveAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest,
      HttpServletRequest request,
      HttpServletResponse response
  ) {
    if (authorizationRequest == null) {
      removeAuthorizationRequestCookies(request, response);
      return;
    }
    CookieUtils.addCookie(
        response,
        OAUTH2_AUTH_REQUEST_COOKIE_NAME,
        serialize(authorizationRequest),
        COOKIE_EXPIRE_SECONDS
    );
  }

  @Override
  public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
    OAuth2AuthorizationRequest req = loadAuthorizationRequest(request);
    removeAuthorizationRequestCookies(request, response);
    return req;
  }

  public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
    CookieUtils.deleteCookie(request, response, OAUTH2_AUTH_REQUEST_COOKIE_NAME);
  }

  private String serialize(Object object) {
    byte[] bytes = SerializationUtils.serialize(object);
    return Base64.getUrlEncoder().encodeToString(bytes);
  }

  private OAuth2AuthorizationRequest deserialize(String cookie) {
    byte[] bytes = Base64.getUrlDecoder().decode(cookie);
    return (OAuth2AuthorizationRequest) SerializationUtils.deserialize(bytes);
  }
}
