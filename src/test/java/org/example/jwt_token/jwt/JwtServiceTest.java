package org.example.jwt_token.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    private SecretKey signingKey;

    private static final long EXPIRATION_MS = 3_600_000L; // 1 hour
    private static final String ISSUER = "test-issuer";

    @BeforeEach
    void setUp() {
        // Key must be at least 256 bits (32 bytes) for HMAC-SHA256
        String secret = "thisIsAVerySecretKeyThatIsLongEnoughForHmacSha256!!";
        signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        jwtService = new JwtService(signingKey, EXPIRATION_MS, ISSUER, userDetailsService);
    }

    // ─── Helper ──────────────────────────────────────────────────────────────

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ─── generateAccessToken tests ────────────────────────────────────────────

    @Test
    @DisplayName("Generated token should not be null or blank")
    void generateAccessToken_shouldReturnNonBlankToken() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        assertThat(token).isNotBlank();
    }

    @Test
    @DisplayName("Token subject should match the username")
    void generateAccessToken_subjectShouldMatchUsername() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        log.info("Generated token: {}", token);

        Claims claims = parseClaims(token);
        assertThat(claims.getSubject()).isEqualTo("alice@example.com");
    }

    @Test
    @DisplayName("Token issuer should match the configured issuer")
    void generateAccessToken_issuerShouldMatchConfigured() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.getIssuer()).isEqualTo(ISSUER);
    }

    @Test
    @DisplayName("Token should not be expired after generation")
    void generateAccessToken_tokenShouldNotBeExpired() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.getExpiration()).isAfter(new Date());
    }

    @Test
    @DisplayName("Token issuedAt should be before or equal to now")
    void generateAccessToken_issuedAtShouldBeInThePast() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        Claims claims = parseClaims(token);
        assertThat(claims.getIssuedAt()).isBeforeOrEqualTo(new Date());
    }

    @Test
    @DisplayName("Token should contain a unique JWT ID (jti)")
    void generateAccessToken_shouldContainUniqueJwtId() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token1 = jwtService.generateAccessToken(user);
        String token2 = jwtService.generateAccessToken(user);

        assertThat(parseClaims(token1).getId()).isNotBlank();
        assertThat(parseClaims(token1).getId())
                .isNotEqualTo(parseClaims(token2).getId()); // each token gets a fresh UUID
    }

    @Test
    @DisplayName("Token roles claim should contain the user's single role")
    void generateAccessToken_shouldEmbedSingleRole() {
        UserDetails user = new User("alice@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) parseClaims(token).get("roles");
        assertThat(roles).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("Token roles claim should contain all of the user's roles")
    void generateAccessToken_shouldEmbedMultipleRoles() {
        UserDetails user = new User("admin@example.com", "password",
                List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                ));

        String token = jwtService.generateAccessToken(user);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) parseClaims(token).get("roles");
        assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("Token with no roles should have an empty roles list")
    void generateAccessToken_shouldEmbedEmptyRolesWhenUserHasNone() {
        UserDetails user = new User("noRole@example.com", "password", List.of());

        String token = jwtService.generateAccessToken(user);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) parseClaims(token).get("roles");
        assertThat(roles).isEmpty();
    }

    // ─── isTokenValid tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("isTokenValid should return true for a freshly generated token")
    void isTokenValid_shouldReturnTrue_forFreshToken() {
        UserDetails user = new User("bob@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenValid(token, user)).isTrue();
    }

    @Test
    @DisplayName("isTokenValid should return false when token belongs to a different user")
    void isTokenValid_shouldReturnFalse_forWrongUser() {
        UserDetails user1 = new User("user1@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        UserDetails user2 = new User("user2@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));

        String token = jwtService.generateAccessToken(user1);

        assertThat(jwtService.isTokenValid(token, user2)).isFalse();
    }

    @Test
    @DisplayName("isTokenValid should return false for an expired token")
    void isTokenValid_shouldReturnFalse_forExpiredToken() {
        // Negative expiration forces the token to already be expired
        JwtService shortLivedService =
                new JwtService(signingKey, -1000L, ISSUER, userDetailsService);

        UserDetails user = new User("expired@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        String token = shortLivedService.generateAccessToken(user);

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    @DisplayName("isTokenValid should return false for a tampered token")
    void isTokenValid_shouldReturnFalse_forTamperedToken() {
        UserDetails user = new User("tampered@example.com", "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER")));
        String token = jwtService.generateAccessToken(user);

        // Corrupt the signature part (last segment)
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "invalidsignature";

        assertThat(jwtService.isTokenValid(tampered, user)).isFalse();
    }
}

