package com.financemanager.finance_manager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Credentials of the first ADMIN, read from {@code app.bootstrap-admin.*}.
 * Both values are optional: when absent, no admin is created at startup.
 */
@ConfigurationProperties(prefix = "app.bootstrap-admin")
public record BootstrapAdminProperties(String email, String password) {

    public boolean isConfigured() {
        return email != null && !email.isBlank() && password != null && !password.isBlank();
    }
}
