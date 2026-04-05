package org.example.jwt_token.user;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Builder
@Getter
@Setter
public class CustomUserDetailsService implements UserDetailsService{

    private final UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));

       UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
               .username(user.getUsername())
               .password(user.getPassowrd())
               .roles(user.getRole())
               .build();

       return userDetails;

    }
}
