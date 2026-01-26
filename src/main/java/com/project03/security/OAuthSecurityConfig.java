package com.project03.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class OAuthSecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http,
      ClientRegistrationRepository registrations) throws Exception {

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
            .requestMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
        )
        .headers(h -> h.frameOptions(f -> f.sameOrigin()))
        .oauth2Login(oauth -> oauth
            .authorizationEndpoint(ae -> ae.baseUri("/oauth2/authorization"))
            // ✅ IMPORTANT: send WebView here after GitHub login
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
    config.setAllowedOriginPatterns(List.of(
        "http://localhost:*",
        "http://127.0.0.1:*",
        "http://10.0.2.2:*",
        "http://192.168.*.*",
        "exp://*",
        "https://*.exp.direct:*"
    ));
    config.setAllowCredentials(true);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "X-Requested-With"));
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }
}
