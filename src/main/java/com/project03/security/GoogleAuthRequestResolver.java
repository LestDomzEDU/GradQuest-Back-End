package com.project03.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.LinkedHashMap;
import java.util.Map;

public class GoogleAuthRequestResolver implements OAuth2AuthorizationRequestResolver {

  private final DefaultOAuth2AuthorizationRequestResolver delegate;

  public GoogleAuthRequestResolver(ClientRegistrationRepository repo, String authorizationRequestBaseUri) {
    this.delegate = new DefaultOAuth2AuthorizationRequestResolver(repo, authorizationRequestBaseUri);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    OAuth2AuthorizationRequest req = delegate.resolve(request);
    return customizeIfNeeded(request, req);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
    OAuth2AuthorizationRequest req = delegate.resolve(request, clientRegistrationId);
    return customizeIfNeeded(request, req);
  }

  private OAuth2AuthorizationRequest customizeIfNeeded(HttpServletRequest request, OAuth2AuthorizationRequest req) {
    if (req == null) return null;

    // Only apply to Google AND only when the caller added ?fresh=1
    String regId = (String) req.getAttributes().getOrDefault("registration_id", "");
    boolean isGoogle = "google".equals(regId);
    boolean wantFresh = "1".equals(request.getParameter("fresh"));

    if (!isGoogle || !wantFresh) return req;

    Map<String, Object> extra = new LinkedHashMap<>(req.getAdditionalParameters());
    extra.put("prompt", "select_account consent");
    extra.put("max_age", "0");

    return OAuth2AuthorizationRequest.from(req)
        .additionalParameters(extra)
        .build();
  }
}
