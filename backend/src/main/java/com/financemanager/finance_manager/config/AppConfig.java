package com.financemanager.finance_manager.config;

import java.time.Clock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({JwtProperties.class, BootstrapAdminProperties.class, CorsProperties.class})
public class AppConfig {

    // Injected wherever "now" is needed, so tests can control time.
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
