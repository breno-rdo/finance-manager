package com.financemanager.finance_manager.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.financemanager.finance_manager.TestcontainersConfiguration;
import com.financemanager.finance_manager.user.Role;
import com.financemanager.finance_manager.user.User;
import com.financemanager.finance_manager.user.UserRepository;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
class AuthIntegrationTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtEncoder jwtEncoder;

    // ---- registration ----

    @Test
    void registerCreatesViewerAndNeverExposesThePassword() throws Exception {
        String email = uniqueEmail();

        register(email, PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("VIEWER"))
                .andExpect(jsonPath("$").value(not(hasKey("password"))))
                .andExpect(jsonPath("$").value(not(hasKey("passwordHash"))));
    }

    @Test
    void registerNormalizesEmailAndRejectsDuplicatesIgnoringCase() throws Exception {
        String email = uniqueEmail();

        register(email.toUpperCase(), PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email));
        register(email, PASSWORD).andExpect(status().isConflict());
    }

    @Test
    void registerRejectsInvalidInput() throws Exception {
        register("not-an-email", "short")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    // ---- login ----

    @Test
    void loginReturnsTokensForValidCredentials() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());

        login(email, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900));
    }

    @Test
    void loginGivesTheSameAnswerForWrongPasswordAndUnknownEmail() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());

        login(email, "wrong-password-123")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
        login(uniqueEmail(), PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password."));
    }

    // ---- access token ----

    @Test
    void healthIsPublic() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    void meReturnsTheIdentityStoredInTheToken() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());
        String accessToken = accessTokenOf(login(email, PASSWORD));

        mockMvc.perform(get("/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("VIEWER"));
    }

    @Test
    void protectedRoutesRejectMissingAndInvalidTokens() throws Exception {
        mockMvc.perform(get("/auth/me")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer garbage"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredTokensAreRejected() throws Exception {
        Instant past = Instant.now().minusSeconds(3600);
        String expired = sign(jwtEncoder, past, past.plusSeconds(60));

        mockMvc.perform(get("/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokensSignedWithAnotherKeyAreRejected() throws Exception {
        byte[] otherKey = "another-secret-key-with-32-bytes-or-more!".getBytes(StandardCharsets.UTF_8);
        JwtEncoder foreignEncoder = new NimbusJwtEncoder(
                new ImmutableSecret<>(new SecretKeySpec(otherKey, "HmacSHA256")));
        Instant now = Instant.now();
        String forged = sign(foreignEncoder, now, now.plusSeconds(600));

        mockMvc.perform(get("/auth/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + forged))
                .andExpect(status().isUnauthorized());
    }

    // ---- role-based authorization ----

    @Test
    void viewerCannotWrite() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());
        String viewerToken = accessTokenOf(login(email, PASSWORD));

        mockMvc.perform(post("/suppliers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + viewerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminPassesTheWriteAuthorization() throws Exception {
        String email = uniqueEmail();
        userRepository.save(new User(email, passwordEncoder.encode(PASSWORD), Role.ADMIN, Instant.now()));
        String adminToken = accessTokenOf(login(email, PASSWORD));

        // /suppliers does not exist yet, so reaching the dispatcher (404) proves security let the ADMIN through.
        int status = mockMvc.perform(post("/suppliers")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andReturn().getResponse().getStatus();
        assertThat(status).isNotIn(401, 403);
    }

    // ---- refresh token ----

    @Test
    void refreshRotatesTheTokenAndTheOldOneStopsWorking() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());
        String first = refreshTokenOf(login(email, PASSWORD));

        ResultActions refreshed = refresh(first).andExpect(status().isOk());
        String second = refreshTokenOf(refreshed);

        assertThat(second).isNotEqualTo(first);
        refresh(first).andExpect(status().isUnauthorized());
    }

    @Test
    void reusingARotatedTokenRevokesEveryActiveSession() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());
        String stolen = refreshTokenOf(login(email, PASSWORD));
        String legitimate = refreshTokenOf(refresh(stolen).andExpect(status().isOk()));

        refresh(stolen).andExpect(status().isUnauthorized());
        // The legitimate session was revoked too, because a reused token signals theft.
        refresh(legitimate).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevokesTheRefreshTokenAndIsIdempotent() throws Exception {
        String email = uniqueEmail();
        register(email, PASSWORD).andExpect(status().isCreated());
        String token = refreshTokenOf(login(email, PASSWORD));

        logout(token).andExpect(status().isNoContent());
        logout(token).andExpect(status().isNoContent());
        refresh(token).andExpect(status().isUnauthorized());
    }

    @Test
    void refreshRejectsUnknownTokens() throws Exception {
        refresh("this-token-was-never-issued").andExpect(status().isUnauthorized());
    }

    // ---- helpers ----

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private ResultActions register(String email, String password) throws Exception {
        return postJson("/auth/register", """
                {"email":"%s","password":"%s"}""".formatted(email, password));
    }

    private ResultActions login(String email, String password) throws Exception {
        return postJson("/auth/login", """
                {"email":"%s","password":"%s"}""".formatted(email, password));
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return postJson("/auth/refresh", """
                {"refreshToken":"%s"}""".formatted(refreshToken));
    }

    private ResultActions logout(String refreshToken) throws Exception {
        return postJson("/auth/logout", """
                {"refreshToken":"%s"}""".formatted(refreshToken));
    }

    private ResultActions postJson(String url, String body) throws Exception {
        return mockMvc.perform(post(url).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private static String accessTokenOf(ResultActions result) throws Exception {
        return JsonPath.read(result.andReturn().getResponse().getContentAsString(), "$.accessToken");
    }

    private static String refreshTokenOf(ResultActions result) throws Exception {
        return JsonPath.read(result.andReturn().getResponse().getContentAsString(), "$.refreshToken");
    }

    private static String sign(JwtEncoder encoder, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("finance-manager")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject("1")
                .claim("email", "someone@example.com")
                .claim("role", "ADMIN")
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
