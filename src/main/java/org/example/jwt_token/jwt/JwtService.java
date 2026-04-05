package org.example.jwt_token.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.sql.Date;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static io.jsonwebtoken.Jwts.parser;

@Service
public class JwtService {

    private final SecretKey signingKey;

    private final long accessTokenExpirationsMs;

    private final String issuer;
    private final UserDetailsService userDetailsService;

    public JwtService(@Value("${jwt.signing.key}") SecretKey signingKey, @Value("${jwt.access.token.expiration}") long accessTokenExpirationsMs, @Value("${jwt.issuer}") String issuer, UserDetailsService userDetailsService) {
        this.signingKey = signingKey;
        this.accessTokenExpirationsMs = accessTokenExpirationsMs;
        this.issuer = issuer;
        this.userDetailsService = userDetailsService;
    }

    /** generate access token for the user
     *
     * @param user
     * @return String Token
     */

    public String generateAccessToken(UserDetails user){
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(accessTokenExpirationsMs);
        List<String> roles = extractRoles(user.getAuthorities());

        return Jwts.builder()
                .subject(user.getUsername())
                .issuer(issuer)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(signingKey)
                .id(UUID.randomUUID().toString())
                .claim("roles", roles)
                .compact();

    }

    private List<String> extractRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    /**
     * reads the JWT and returns its claims (data stored inside the token)
     * @param token
     * @return Claims
     *
     */
    public Claims parseClaims(String token){
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        try{
            Claims claims = parseClaims(token);
            String username = claims.getSubject();
            String tokenIssuer = claims.getIssuer();
            java.util.Date expiration = claims.getExpiration();

            return username.equals(userDetails.getUsername()) && tokenIssuer.equals(issuer) && expiration.after(new java.util.Date());

        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }
}
