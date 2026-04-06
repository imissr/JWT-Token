package org.example.jwt_token.auth;

import lombok.RequiredArgsConstructor;
import org.example.jwt_token.jwt.JwtService;
import org.example.jwt_token.role.Role;
import org.example.jwt_token.user.User;
import org.example.jwt_token.user.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service handling user registration and login logic.
 * Produces JWT tokens upon successful authentication.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    /**
     * Registers a new user, saves them to the database with a BCrypt-hashed password,
     * and returns a JWT token.
     *
     * @param registerRequest the registration payload containing username and password
     * @return {@link AuthResponse} with JWT token and user info
     * @throws IllegalArgumentException if the username is blank or already taken
     */
    public AuthResponse register(RegisterRequest registerRequest){
        String normalizedUsername = registerRequest.getUsername().trim().toLowerCase();

        if(normalizedUsername.isEmpty() || normalizedUsername.isBlank()){
            throw new IllegalArgumentException("Username cannot be empty");
        }
        if(userRepository.existsByUsername(normalizedUsername)){
            throw new IllegalArgumentException("Username already exists");
        }

        User user = User.builder()
                .username(normalizedUsername)
                .passowrd(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String token = jwtService.generateAccessToken(userDetails);
        String role = userDetails.getAuthorities().iterator().next().getAuthority();

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirationMs())
                .username(userDetails.getUsername())
                .role(role)
                .build();
    }

    /**
     * Authenticates an existing user by verifying credentials against the database.
     * Delegates to {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider},
     * which uses {@link org.example.jwt_token.user.CustomUserDetailsService} and BCrypt password matching.
     *
     * @param authRequest the login payload containing username and password
     * @return {@link AuthResponse} with JWT token and user info
     * @throws org.springframework.security.authentication.BadCredentialsException if credentials are invalid
     */
    public AuthResponse login(AuthRequest authRequest) {
        // Delegates to DaoAuthenticationProvider → CustomUserDetailsService + PasswordEncoder
        // Throws BadCredentialsException automatically if credentials are wrong
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getUsername().trim().toLowerCase(),
                        authRequest.getPassword()
                )
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(
                authRequest.getUsername().trim().toLowerCase()
        );
        String token = jwtService.generateAccessToken(userDetails);
        String role = userDetails.getAuthorities().iterator().next().getAuthority();

        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .expiresIn(jwtService.getAccessTokenExpirationMs())
                .username(userDetails.getUsername())
                .role(role)
                .build();
    }


}
