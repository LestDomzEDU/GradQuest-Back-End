package com.project03.controller;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class OAuthDebugController {

  private final ClientRegistrationRepository repo;

  public OAuthDebugController(ClientRegistrationRepository repo) {
    this.repo = repo;
  }

  @GetMapping("/debug/oauth/clients")
  public Map<String, Object> clients() {
    List<Map<String, Object>> list = new ArrayList<>();

    // The repo is an InMemoryClientRegistrationRepository in our config
    if (repo instanceof Iterable<?> iterable) {
      for (Object o : iterable) {
        ClientRegistration cr = (ClientRegistration) o;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("registrationId", cr.getRegistrationId());
        m.put("clientName", cr.getClientName());
        m.put("scopes", cr.getScopes());
        m.put("authorizationUri", cr.getProviderDetails().getAuthorizationUri());
        m.put("tokenUri", cr.getProviderDetails().getTokenUri());
        m.put("userInfoUri", cr.getProviderDetails().getUserInfoEndpoint().getUri());
        list.add(m);
      }
    }
    return Map.of("clients", list);
  }
}
