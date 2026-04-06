package org.example.jwt_token.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Custom implementation of {@link UserDetailsService} that loads users from the database.
 * Used by Spring Security's {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
 * during authentication to retrieve user details by username.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a user from the database by username and converts it to Spring Security's {@link UserDetails}.
     * The role is automatically prefixed with "ROLE_" (e.g. USER → ROLE_USER).
     *
     * @param username the username to look up
     * @return the matching {@link UserDetails}
     * @throws UsernameNotFoundException if no user with the given username exists
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassowrd())
                .roles(user.getRole().name()) // "USER" → "ROLE_USER"
                .build();
    }
}
