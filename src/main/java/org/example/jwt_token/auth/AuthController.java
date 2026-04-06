package org.example.jwt_token.auth;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller handling authentication endpoints.
 * All routes are publicly accessible (permitted in SecurityConfig).
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    /**
     * Registers a new user and returns a JWT token.
     *
     * @param registerRequest contains the username and password for the new account
     * @return 201 Created with an {@link AuthResponse} containing the JWT token
     */
    @RequestMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest){
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(registerRequest));
    }

    /**
     * Authenticates an existing user and returns a JWT token.
     *
     * @param request contains the username and password to authenticate
     * @return 200 OK with an {@link AuthResponse} containing the JWT token
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
