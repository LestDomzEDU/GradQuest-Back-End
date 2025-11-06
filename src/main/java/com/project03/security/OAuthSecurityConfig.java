package com.project03.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class OAuthSecurityConfig {
  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable())
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/", "/index.html", "/error", "/api/me", "/api/logout", "/debug/**").permitAll()
          .requestMatchers("/oauth2/**", "/login/**", "/logout").permitAll()
          .anyRequest().authenticated()
      )
      .oauth2Login(oauth -> oauth
          .defaultSuccessUrl("/api/me", true)
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
