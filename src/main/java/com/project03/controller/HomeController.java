package com.project03.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

  @GetMapping("/")
  public String index() {
    return """
      <html>
        <head><title>Project 3</title></head>
        <body style="font-family: sans-serif;">
          <h1>Project 3 Back-End</h1>
          <p>
            <a href="/oauth2/authorization/github">Login with GitHub</a>
          </p>
          <p>
            Check auth status: <a href="/api/me">/api/me</a>
          </p>
        </body>
      </html>
      """;
  }
}
