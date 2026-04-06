package org.example.jwt_token.config;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Central Spring Security configuration.
 * Defines the security filter chain, authentication provider, password encoder,
 * and access control rules for all HTTP endpoints.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /**
     * Configures the security filter chain:
     * <ul>
     *   <li>Disables CSRF (stateless API)</li>
     *   <li>Sets session management to stateless (JWT-based)</li>
     *   <li>Permits {@code /auth/**} and {@code GET /demo/public} without authentication</li>
     *   <li>Restricts {@code /demo/admin/**} to ADMIN role</li>
     *   <li>Requires authentication for all other requests</li>
     *   <li>Adds {@link JwtAuthenticationFilter} before the default username/password filter</li>
     * </ul>
     *
     * @param http the {@link HttpSecurity} to configure
     * @return the built {@link SecurityFilterChain}
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf((csrf) -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider())
            .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers(
                            "/auth/**",
                            "/error"
                    ).permitAll()
                    .requestMatchers(HttpMethod.GET, "/demo/public").permitAll()
                    .requestMatchers("/demo/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .build();

    }
    /**
     * Configures the authentication provider using {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}.
     * Wires in the custom {@link UserDetailsService} and BCrypt password encoder.
     *
     * @return the configured {@link AuthenticationProvider}
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    /**
     * Provides a BCrypt password encoder bean used for hashing and verifying passwords.
     *
     * @return a {@link BCryptPasswordEncoder} instance
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * Exposes Spring's {@link AuthenticationManager} as a bean so it can be injected
     * into {@link org.example.jwt_token.auth.AuthService} for manual authentication.
     *
     * @param config the authentication configuration
     * @return the {@link AuthenticationManager}
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }


}
