package com.financemanager.finance_manager.user;

import com.financemanager.finance_manager.config.BootstrapAdminProperties;
import java.time.Clock;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates the first ADMIN at startup from APP_ADMIN_EMAIL / APP_ADMIN_PASSWORD.
 * Public registration only creates VIEWERs, so without this nobody could ever write data.
 * Idempotent: if the email already exists, nothing happens.
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final BootstrapAdminProperties properties;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;

    public AdminBootstrap(BootstrapAdminProperties properties, UserRepository userRepository,
                          PasswordEncoder passwordEncoder, Clock clock) {
        this.properties = properties;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isConfigured()) {
            return;
        }
        if (properties.password().length() < 8) {
            throw new IllegalStateException("APP_ADMIN_PASSWORD must have at least 8 characters.");
        }
        String email = properties.email().trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(email)) {
            return;
        }
        userRepository.save(new User(email, passwordEncoder.encode(properties.password()), Role.ADMIN, clock.instant()));
        log.info("Bootstrap admin created: {}", email);
    }
}
