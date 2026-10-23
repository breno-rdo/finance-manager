package com.financemanager.finance_manager.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.financemanager.finance_manager.config.BootstrapAdminProperties;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

class AdminBootstrapTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);

    private AdminBootstrap bootstrap(String email, String password) {
        return new AdminBootstrap(new BootstrapAdminProperties(email, password),
                userRepository, passwordEncoder, Clock.systemUTC());
    }

    @Test
    void createsTheAdminWithANormalizedEmailAndAHashedPassword() {
        when(passwordEncoder.encode("a-strong-password")).thenReturn("hashed");

        bootstrap("  Admin@Example.com ", "a-strong-password").run(null);

        ArgumentCaptor<User> saved = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("admin@example.com");
        assertThat(saved.getValue().getRole()).isEqualTo(Role.ADMIN);
        assertThat(saved.getValue().getPasswordHash()).isEqualTo("hashed");
    }

    @Test
    void doesNothingWhenNotConfigured() {
        bootstrap("", "").run(null);

        verify(userRepository, never()).save(any());
    }

    @Test
    void doesNotCreateTheAdminTwice() {
        when(userRepository.existsByEmail("admin@example.com")).thenReturn(true);

        bootstrap("admin@example.com", "a-strong-password").run(null);

        verify(userRepository, never()).save(any());
    }

    @Test
    void failsFastWhenThePasswordIsTooShort() {
        assertThatThrownBy(() -> bootstrap("admin@example.com", "short").run(null))
                .isInstanceOf(IllegalStateException.class);
        verify(userRepository, never()).save(any());
    }
}
