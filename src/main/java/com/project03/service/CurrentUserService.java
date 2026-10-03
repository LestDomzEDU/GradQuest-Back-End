package com.project03.service;

import com.project03.model.User;
import com.project03.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

/**
 * Resolves the logged-in User from the session. Controllers must use this instead of
 * accepting a userId from the request, so one user can never read or change another's data.
 */
@Service
public class CurrentUserService {

    private final UserRepository userRepository;
    private final OAuthUserService oauthUserService;

    public CurrentUserService(UserRepository userRepository, OAuthUserService oauthUserService) {
        this.userRepository = userRepository;
        this.oauthUserService = oauthUserService;
    }

    public Optional<User> find(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            return Optional.empty();
        }
        OAuth2User principal = token.getPrincipal();
        String provider = token.getAuthorizedClientRegistrationId().toLowerCase();

        Object idAttr = "google".equals(provider) ? principal.getAttribute("sub") : principal.getAttribute("id");
        if (idAttr != null) {
            Optional<User> existing =
                userRepository.findByOauthProviderAndOauthProviderId(provider, String.valueOf(idAttr));
            if (existing.isPresent()) {
                return existing;
            }
        }
        return Optional.of(oauthUserService.getOrCreateUser(principal, provider));
    }

    /** Returns the logged-in user, or responds 401 if there isn't one. */
    public User require(Authentication authentication) {
        return find(authentication)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not signed in"));
    }
}
