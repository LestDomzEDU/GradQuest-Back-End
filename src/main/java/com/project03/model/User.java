package com.project03.model;

import jakarta.persistence.*;

/**
 * User entity for OAuth-based login.
 * NOTE: GitHub may not always provide an email, so email must be nullable.
 */
@Entity
@Table(
    name = "app_users",
    uniqueConstraints = {
        // Ensure we don't create duplicate users for the same provider identity
        @UniqueConstraint(columnNames = {"oauth_provider", "oauth_provider_id"})
    }
)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Email can be null for GitHub OAuth depending on account/privacy settings.
    // In MySQL/MariaDB, UNIQUE allows multiple NULL values, so this is safe.
    @Column(name = "email", unique = true, nullable = true)
    private String email;

    @Column(name = "name", nullable = true)
    private String name;

    // OAuth provider (e.g., "github")
    @Column(name = "oauth_provider", nullable = false)
    private String oauthProvider;

    // OAuth provider user ID (e.g., GitHub id)
    @Column(name = "oauth_provider_id", nullable = false)
    private String oauthProviderId;

    // Avatar URL from OAuth provider
    @Column(name = "avatar_url", nullable = true)
    private String avatarUrl;

    // Constructors
    public User() {}

    public User(String email, String name) {
        this.email = email;
        this.name = name;
    }

    public User(String email, String name, String oauthProvider, String oauthProviderId) {
        this.email = email;
        this.name = name;
        this.oauthProvider = oauthProvider;
        this.oauthProviderId = oauthProviderId;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getOauthProvider() { return oauthProvider; }
    public void setOauthProvider(String oauthProvider) { this.oauthProvider = oauthProvider; }

    public String getOauthProviderId() { return oauthProviderId; }
    public void setOauthProviderId(String oauthProviderId) { this.oauthProviderId = oauthProviderId; }

    public String getAvatarUrl() { return avatarUrl; }
    public void setAvatarUrl(String avatarUrl) { this.avatarUrl = avatarUrl; }
}
