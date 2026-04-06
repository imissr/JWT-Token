package org.example.jwt_token.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.jwt_token.jwt.JwtService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that runs once per request to validate the JWT token in the Authorization header.
 * If a valid Bearer token is present, the user is authenticated in the {@link SecurityContextHolder}.
 * Requests without a token (or with an invalid one) pass through unauthenticated,
 * and Spring Security's access rules decide whether to allow or reject them.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * Intercepts each HTTP request, extracts the Bearer token from the Authorization header,
     * validates it, and sets the authentication in the security context if valid.
     *
     * @param request     the incoming HTTP request
     * @param response    the HTTP response
     * @param filterChain the remaining filter chain
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        String username;

        try{
            username = jwtService.extractUsername(token);
        }catch(Exception e){
            filterChain.doFilter(request, response);
            return;
        }

        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if(jwtService.isTokenValid(token, userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        filterChain.doFilter(request, response);

    }
}
