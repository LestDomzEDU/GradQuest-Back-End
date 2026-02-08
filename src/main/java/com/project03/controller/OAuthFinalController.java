package com.project03.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuthFinalController {

  @GetMapping("/oauth2/final")
  public String done() {
    return """
      <html>
        <head>
          <meta name="viewport" content="width=device-width,initial-scale=1"/>
          <title>Signed in</title>
        </head>
        <body style="font-family:sans-serif;padding:16px">
          <h2>✅ Signed in with GitHub</h2>
          <p>You can now return to the app.</p>
          <p><a href="/api/me">View session (/api/me)</a></p>
          <p><a href="/">Home</a></p>
        </body>
      </html>
      """;
  }
}
