package com.project03.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class OAuthSecurityConfig {

  /**
   * Frontend base URL (used for CORS).
   * In prod, set APP_BASE_URL in Heroku and application-prod.properties maps it to frontend.base.
   */
  @Value("${frontend.base:http://localhost:8081}")
  private String frontendBase;

  /**
   * Optional extra CORS origins (comma-separated). Useful when testing from Expo/device, etc.
   * Example:
   *   CORS_ALLOWED_ORIGINS=exp://10.0.2.2:8081,http://10.0.2.2:8081
   */
  @Value("${cors.allowed-origins:}")
  private String extraCorsOrigins;

  @Bean
  SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      ClientRegistrationRepository registrations,
      OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient
  ) throws Exception {

    http
        .cors(Customizer.withDefaults())
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(
                "/", "/index.html", "/error",
                "/api/me", "/api/logout",
                "/oauth2/final", "/debug/**"
            ).permitAll()
            .requestMatchers("/oauth2/**", "/login/**", "/logout").permitAll()
            // NOTE: You currently allow /api/** without auth. If you later want to lock down APIs,
            // change this to authenticated() and permit only the public endpoints.
            .requestMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
        )
        .headers(h -> h.frameOptions(f -> f.sameOrigin()))
        .oauth2Login(oauth -> oauth
            .authorizationEndpoint(ae -> ae.baseUri("/oauth2/authorization"))
            // Required for GitHub in some cases so it returns JSON token responses cleanly
            .tokenEndpoint(te -> te.accessTokenResponseClient(accessTokenResponseClient))
            .defaultSuccessUrl("/oauth2/final", true)
            .failureUrl("/?login=failed")
        )
        .logout(logout -> logout
            .logoutUrl("/api/logout")
            .logoutSuccessUrl("/")
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID")
        );

    return http.build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();

    List<String> originPatterns = new ArrayList<>();

    // Frontend base from properties/env (recommended)
    if (frontendBase != null && !frontendBase.isBlank()) {
      originPatterns.add(stripTrailingSlash(frontendBase.trim()));
    }

    // Common local dev origins
    originPatterns.addAll(List.of(
        "http://localhost:8081",
        "http://127.0.0.1:8081",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://10.0.2.2:8081",
        "exp://10.0.2.2:8081"
    ));

    // Extra origins (comma-separated)
    if (extraCorsOrigins != null && !extraCorsOrigins.isBlank()) {
      Arrays.stream(extraCorsOrigins.split(","))
          .map(String::trim)
          .filter(s -> !s.isBlank())
          .map(OAuthSecurityConfig::stripTrailingSlash)
          .forEach(originPatterns::add);
    }

    config.setAllowedOriginPatterns(originPatterns);
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "X-Requested-With"));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  private static String stripTrailingSlash(String s) {
    while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
    return s;
  }
}
