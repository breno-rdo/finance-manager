package com.financemanager.finance_manager.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.financemanager.finance_manager.TestcontainersConfiguration;
import com.financemanager.finance_manager.auth.dto.LoginRequest;
import com.financemanager.finance_manager.auth.dto.RegisterRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class RefreshConcurrencyTest {

    @Autowired
    private AuthService authService;

    @Test
    void onlyOneOfManySimultaneousRefreshesWithTheSameTokenSucceeds() throws Exception {
        String email = "race-" + UUID.randomUUID() + "@example.com";
        authService.register(new RegisterRequest(email, "correct-horse-battery"));
        String token = authService.login(new LoginRequest(email, "correct-horse-battery")).refreshToken();

        int threads = 8;
        CountDownLatch startTogether = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Callable<Boolean> attempt = () -> {
                startTogether.await();
                try {
                    authService.refresh(token);
                    return true;
                } catch (InvalidRefreshTokenException e) {
                    return false;
                }
            };
            results.add(pool.submit(attempt));
        }
        startTogether.countDown();

        long successes = 0;
        for (Future<Boolean> result : results) {
            if (result.get()) {
                successes++;
            }
        }
        pool.shutdown();

        assertThat(successes).isEqualTo(1);
    }
}
