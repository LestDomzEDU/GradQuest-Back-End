package com.project03.service;

import com.project03.model.User;
import com.project03.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * Service to handle OAuth user creation and updates.
 * Automatically creates or updates User records when users sign in via OAuth.
 */
@Service
public class OAuthUserService {

    private final UserRepository userRepository;

    @Autowired
    public OAuthUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Get or create a User from OAuth2User.
     * This method extracts OAuth provider information and creates/updates the User record.
     *
     * @param oauth2User     The OAuth2User from Spring Security
     * @param registrationId The OAuth registration ID ("github", "google", or "discord")
     * @return The User entity (existing or newly created)
     */
    @Transactional
    public User getOrCreateUser(OAuth2User oauth2User, String registrationId) {
        Map<String, Object> attrs = oauth2User.getAttributes();

        String oauthProvider = registrationId.toLowerCase(); // "github", "google", "discord"
        String oauthProviderId;
        String email;
        String name;
        String avatarUrl = null;

        // Extract provider-specific information
        if ("github".equals(oauthProvider)) {
            // GitHub attributes
            Object idObj = attrs.get("id");
            oauthProviderId = idObj != null ? String.valueOf(idObj) : null;

            // GitHub may have email in user:email scope, but it might be private
            email = (String) attrs.get("email");
            if (email == null || email.isEmpty()) {
                // Try to construct from login if email is not available
                String login = (String) attrs.get("login");
                if (login != null) {
                    email = login + "@github.noreply"; // Fallback if email is private
                }
            }

            name = (String) attrs.get("name");
            if (name == null || name.isEmpty()) {
                name = (String) attrs.get("login"); // Fallback to login if name is not set
            }

            avatarUrl = (String) attrs.get("avatar_url");
        } else if ("google".equals(oauthProvider)) {
            // Google OIDC attributes
            oauthProviderId = (String) attrs.get("sub");
            email = (String) attrs.get("email");
            name = (String) attrs.get("name");
            avatarUrl = (String) attrs.get("picture");
        } else if ("discord".equals(oauthProvider)) {
            // Discord attributes from /users/@me
            Object idObj = attrs.get("id");
            oauthProviderId = idObj != null ? String.valueOf(idObj) : null;

            email = (String) attrs.get("email");
            String username = (String) attrs.get("username");
            String globalName = (String) attrs.get("global_name");

            // Email can be null if not verified / not shared; fall back to synthetic
            if (email == null || email.isEmpty()) {
                if (username != null && !username.isEmpty()) {
                    email = username + "@discord.noreply";
                }
            }

            // Pick best display name
            if (globalName != null && !globalName.isEmpty()) {
                name = globalName;
            } else if (username != null && !username.isEmpty()) {
                name = username;
            } else if (email != null && !email.isEmpty()) {
                name = email;
            } else {
                name = "Discord User";
            }

            // Build avatar URL if avatar hash exists
            String avatarHash = (String) attrs.get("avatar");
            if (avatarHash != null && !avatarHash.isEmpty() && idObj != null) {
                avatarUrl = "https://cdn.discordapp.com/avatars/"
                        + oauthProviderId + "/" + avatarHash + ".png";
            }
        } else if ("dev".equals(oauthProvider)) {
            // Local test users created by DevLoginController (dev profile only)
            Object idObj = attrs.get("id");
            oauthProviderId = idObj != null ? String.valueOf(idObj) : null;
            email = (String) attrs.get("email");
            name = (String) attrs.get("name");
        } else {
            throw new IllegalArgumentException("Unsupported OAuth provider: " + registrationId);
        }

        // Validate required fields
        if (oauthProviderId == null || oauthProviderId.isEmpty()) {
            throw new IllegalStateException("OAuth provider ID is missing for provider: " + oauthProvider);
        }

        // Try to find existing user by OAuth provider and provider ID
        Optional<User> existingUserOpt = userRepository.findByOauthProviderAndOauthProviderId(
            oauthProvider, oauthProviderId);

        User user;
        if (existingUserOpt.isPresent()) {
            // Update existing user
            user = existingUserOpt.get();

            // Update fields if they've changed
            if (email != null && !email.isEmpty() && !email.equals(user.getEmail())) {
                // Check if email is already taken by another user
                Optional<User> emailUser = userRepository.findByEmail(email);
                if (emailUser.isEmpty() || emailUser.get().getId().equals(user.getId())) {
                    user.setEmail(email);
                }
            }

            if (name != null && !name.isEmpty()) {
                user.setName(name);
            }

            if (avatarUrl != null && !avatarUrl.isEmpty()) {
                user.setAvatarUrl(avatarUrl);
            }

            user = userRepository.save(user);
        } else {
            // Check if user exists by email (in case they signed in with different provider)
            // Only check by email if email is valid and not a fallback
            // Note: Email has unique constraint, so we update existing user if email matches
            boolean emailLooksReal =
                email != null && !email.isEmpty() && !email.endsWith("@github.noreply") && !email.endsWith("@discord.noreply");

            if (emailLooksReal) {
                Optional<User> emailUserOpt = userRepository.findByEmail(email);
                if (emailUserOpt.isPresent()) {
                    // User exists with same email - update to use current OAuth provider
                    // (Email is unique, so we can't have separate accounts per provider)
                    user = emailUserOpt.get();
                    user.setOauthProvider(oauthProvider);
                    user.setOauthProviderId(oauthProviderId);
                    if (name != null && !name.isEmpty()) {
                        user.setName(name);
                    }
                    if (avatarUrl != null && !avatarUrl.isEmpty()) {
                        user.setAvatarUrl(avatarUrl);
                    }
                    user = userRepository.save(user);
                } else {
                    // Create new user with email
                    user = new User();
                    user.setEmail(email);
                    user.setName(name);
                    user.setOauthProvider(oauthProvider);
                    user.setOauthProviderId(oauthProviderId);
                    user.setAvatarUrl(avatarUrl);
                    user = userRepository.save(user);
                }
            } else {
                // Create new user without email or with fallback email
                user = new User();
                if (email != null && !email.isEmpty()) {
                    user.setEmail(email);
                }
                if (name != null && !name.isEmpty()) {
                    user.setName(name);
                }
                user.setOauthProvider(oauthProvider);
                user.setOauthProviderId(oauthProviderId);
                if (avatarUrl != null && !avatarUrl.isEmpty()) {
                    user.setAvatarUrl(avatarUrl);
                }
                user = userRepository.save(user);
            }
        }

        return user;
    }

    /**
     * Determine the OAuth registration ID from the OAuth2User attributes.
     * This is a fallback method if registrationId is not available.
     */
    public String detectProvider(OAuth2User oauth2User) {
        Map<String, Object> attrs = oauth2User.getAttributes();

        // Check for GitHub-specific attributes
        if (attrs.containsKey("login") || attrs.containsKey("avatar_url")) {
            return "github";
        }

        // Check for Google-specific attributes
        if (attrs.containsKey("sub") || attrs.containsKey("picture")) {
            return "google";
        }

        // Check for Discord-specific attributes
        if (attrs.containsKey("username") || attrs.containsKey("global_name")) {
            return "discord";
        }

        // Default fallback
        return "unknown";
    }
}
