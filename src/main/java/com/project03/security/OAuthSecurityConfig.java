package com.project03.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuthSecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http,
                                          ClientRegistrationRepository registrations) throws Exception {
    http
      .csrf(csrf -> csrf.disable())
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/", "/index.html", "/error",
                           "/api/me", "/api/logout",
                           "/oauth2/final", "/debug/**").permitAll()
          .requestMatchers("/oauth2/**", "/login/**", "/logout").permitAll()
          .anyRequest().authenticated()
      )
      .oauth2Login(oauth -> oauth
          .authorizationEndpoint(ep -> ep
              .authorizationRequestResolver(new GoogleAuthRequestResolver(registrations, "/oauth2/authorization"))
          )
          // IMPORTANT: after successful OAuth, go to the close-tab page, not /api/me
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
}
