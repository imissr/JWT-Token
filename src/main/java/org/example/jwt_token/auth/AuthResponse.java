package org.example.jwt_token.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor
public class AuthResponse {

    private final String token;
    private final String tokenType;
    private final long expiresIn;
    private final String username;
    private final String role;
}
