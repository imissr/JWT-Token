package org.example.jwt_token.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Strongly-typed configuration properties for JWT, bound from {@code app.jwt.*} in application.properties/yml.
 * Validated on startup to ensure all required fields are present and valid.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    /** The secret key used for HMAC-SHA token signing. Must not be blank. */
    @NotBlank
    private String secret;

    /** Token expiration duration in milliseconds. Must be at least 60000 (1 minute). */
    @Min(60000)
    private long expiration;

    /** The expected issuer claim embedded in every token. Must not be blank. */
    @NotBlank
    private String issuer;
}