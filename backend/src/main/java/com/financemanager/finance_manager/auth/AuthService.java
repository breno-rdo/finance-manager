package com.financemanager.finance_manager.auth;

import com.financemanager.finance_manager.auth.dto.LoginRequest;
import com.financemanager.finance_manager.auth.dto.RegisterRequest;
import com.financemanager.finance_manager.auth.dto.TokenResponse;
import com.financemanager.finance_manager.auth.dto.UserResponse;
import com.financemanager.finance_manager.common.validation.MaxBytesValidator;
import com.financemanager.finance_manager.config.JwtProperties;
import com.financemanager.finance_manager.user.Role;
import com.financemanager.finance_manager.user.User;
import com.financemanager.finance_manager.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    /** BCrypt only uses the first 72 bytes of a password. */
    public static final int MAX_PASSWORD_BYTES = 72;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final Clock clock;
    // Compared against when the email does not exist, so both failures take similar time.
    private final String dummyHash;

    public AuthService(UserRepository userRepository, RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder, JwtService jwtService,
                       JwtProperties jwtProperties, Clock clock) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.clock = clock;
        this.dummyHash = passwordEncoder.encode("not-a-real-password");
    }

    /** Public registration always creates a VIEWER; only the bootstrap admin or an ADMIN gets more. */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        String email = normalize(request.email());
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyUsedException();
        }
        User user = new User(email, passwordEncoder.encode(request.password()), Role.VIEWER, clock.instant());
        try {
            return UserResponse.from(userRepository.saveAndFlush(user));
        } catch (DataIntegrityViolationException e) {
            // Two simultaneous registrations passed the check above; the unique index caught the second.
            throw new EmailAlreadyUsedException();
        }
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        // No stored password can exceed BCrypt's limit, so this cannot match; also avoids an encoder error.
        if (MaxBytesValidator.exceeds(request.password(), MAX_PASSWORD_BYTES)) {
            throw new InvalidCredentialsException();
        }
        User user = userRepository.findByEmail(normalize(request.email())).orElse(null);
        String hash = user != null ? user.getPasswordHash() : dummyHash;
        boolean matches = passwordEncoder.matches(request.password(), hash);
        if (user == null || !matches) {
            throw new InvalidCredentialsException();
        }
        return issueTokens(user);
    }

    /**
     * Rotation: each refresh token works once. Presenting an already-used token means it may have been
     * stolen, so every active session of that user is revoked. noRollbackFor keeps that revocation
     * from being undone when the exception is thrown.
     */
    @Transactional(noRollbackFor = InvalidRefreshTokenException.class)
    public TokenResponse refresh(String rawRefreshToken) {
        Instant now = clock.instant();
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash(rawRefreshToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        if (stored.isExpired(now)) {
            throw new InvalidRefreshTokenException();
        }
        // The check and the revocation are one atomic statement, so two simultaneous requests with the
        // same token cannot both succeed. A token that was already revoked (earlier or a moment ago
        // by a concurrent request) is treated as reuse.
        if (stored.isRevoked() || refreshTokenRepository.revokeIfActive(stored.getId(), now) == 0) {
            refreshTokenRepository.revokeAllActiveByUserId(stored.getUser().getId(), now);
            throw new InvalidRefreshTokenException();
        }
        return issueTokens(stored.getUser());
    }

    /** Idempotent: an unknown or already revoked token is not an error. */
    @Transactional
    public void logout(String rawRefreshToken) {
        refreshTokenRepository.findByTokenHash(hash(rawRefreshToken))
                .filter(token -> !token.isRevoked())
                .ifPresent(token -> token.revoke(clock.instant()));
    }

    private TokenResponse issueTokens(User user) {
        Instant now = clock.instant();
        String rawRefreshToken = generateRawToken();
        refreshTokenRepository.save(new RefreshToken(
                user, hash(rawRefreshToken), now.plus(jwtProperties.refreshTokenTtl()), now));
        return TokenResponse.bearer(
                jwtService.generateAccessToken(user), rawRefreshToken, jwtService.accessTokenTtlSeconds());
    }

    /** 256 random bits; the client receives this value, the database only keeps its hash. */
    private static String generateRawToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** SHA-256 is enough here (unlike passwords): the token is random, so it cannot be guessed offline. */
    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
