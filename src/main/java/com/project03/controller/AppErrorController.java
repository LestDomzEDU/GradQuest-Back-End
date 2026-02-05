package com.project03.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class AppErrorController implements ErrorController {

  @GetMapping("/error")
  public Object handleError(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

    // If OAuth sends code/state to /error, forward it to the real Spring Security callback endpoint.
    String code = request.getParameter("code");
    String state = request.getParameter("state");

    if (StringUtils.hasText(code) && StringUtils.hasText(state)) {
      // Basic provider guess:
      // Google commonly includes "scope=openid", GitHub typically doesn't.
      String scope = request.getParameter("scope");
      String provider = (scope != null && scope.toLowerCase().contains("openid")) ? "google" : "github";

      String forwardPath = "/login/oauth2/code/" + provider;

      // Forward keeps session + saved authorization request intact (key fix).
      RequestDispatcher dispatcher = request.getRequestDispatcher(forwardPath);
      dispatcher.forward(request, response);
      return null; // response already handled
    }

    // Normal JSON error output (instead of Whitelabel)
    Object statusObj = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
    int status = statusObj instanceof Integer ? (Integer) statusObj : 500;

    Object messageObj = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
    Object exceptionObj = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("status", status);
    body.put("path", request.getRequestURI());
    body.put("query", request.getQueryString());
    body.put("message", messageObj);

    if (exceptionObj != null) {
      body.put("exception", exceptionObj.getClass().getName());
    }

    return ResponseEntity.status(HttpStatus.valueOf(status)).body(body);
  }
}
