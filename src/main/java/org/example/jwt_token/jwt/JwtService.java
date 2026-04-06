package org.example.jwt_token.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.example.jwt_token.config.JwtProperties;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Service responsible for all JWT operations: generation, parsing, and validation.
 * Uses HMAC-SHA signing with the secret key defined in {@link JwtProperties}.
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    /**
     * Builds the HMAC-SHA signing key from the Base64-encoded secret in application properties.
     *
     * @return the {@link SecretKey} used to sign and verify tokens
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Base64.getEncoder().encode(jwtProperties.getSecret().getBytes());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Returns the access token expiration duration in milliseconds.
     *
     * @return expiration time in ms as configured in {@link JwtProperties}
     */
    public long getAccessTokenExpirationMs() {
        return jwtProperties.getExpiration();
    }

    /**
     * Generates a signed JWT access token for the given user.
     * The token includes the username as subject, issuer, issued-at, expiration,
     * a unique JWT ID, and the user's roles as a claim.
     *
     * @param userDetails the authenticated user
     * @return a compact signed JWT string
     */
    public String generateAccessToken(UserDetails userDetails) {
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(jwtProperties.getExpiration());
        List<String> roles = extractRoles(userDetails.getAuthorities());

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getSigningKey())
                .id(UUID.randomUUID().toString())
                .claim("roles", roles)
                .compact();
    }

    /**
     * Extracts role names from a collection of {@link GrantedAuthority} objects.
     *
     * @param authorities the user's granted authorities
     * @return list of authority strings (e.g. ["ROLE_USER"])
     */
    private List<String> extractRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    /**
     * Parses and verifies the JWT signature, returning all claims from the token payload.
     *
     * @param token the compact JWT string
     * @return the {@link Claims} payload
     * @throws io.jsonwebtoken.JwtException if the token is invalid or tampered
     */
    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Extracts the username (subject) from the token.
     *
     * @param token the compact JWT string
     * @return the username stored in the token subject
     */
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Validates the token by checking:
     * <ul>
     *   <li>Username matches the given {@link UserDetails}</li>
     *   <li>Issuer matches the configured issuer</li>
     *   <li>Token has not expired</li>
     * </ul>
     *
     * @param token       the compact JWT string
     * @param userDetails the user to validate against
     * @return {@code true} if the token is valid, {@code false} otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = parseClaims(token);
            String username = claims.getSubject();
            String tokenIssuer = claims.getIssuer();
            java.util.Date expiration = claims.getExpiration();

            return username.equals(userDetails.getUsername())
                    && tokenIssuer.equals(jwtProperties.getIssuer())
                    && expiration.after(new java.util.Date());

        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
