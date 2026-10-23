package com.financemanager.finance_manager.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Typed binding for the {@code app.jwt.*} properties in application.yml.
 * Validation makes the application fail at startup (not at the first login) when the config is wrong.
 */
@Validated
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        // HS256 needs a key of at least 256 bits (32 bytes).
        @NotBlank @Size(min = 32) String secret,
        @NotBlank String issuer,
        @NotNull Duration accessTokenTtl,
        @NotNull Duration refreshTokenTtl) {
}
