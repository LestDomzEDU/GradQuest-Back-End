package com.project03.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthFinalController {

  @GetMapping("/oauth2/final")
  public String closeTab() {
    return """
      <html>
        <head><meta name="viewport" content="width=device-width,initial-scale=1"/></head>
        <body style="font-family:sans-serif">
          <script>
            try { window.close(); } catch(e) {}
            setTimeout(function(){ window.location.href='/api/me'; }, 10);
          </script>
          <noscript>
            <p>Signed in. <a href="/api/me">Continue</a></p>
          </noscript>
        </body>
      </html>
      """;
  }
}
