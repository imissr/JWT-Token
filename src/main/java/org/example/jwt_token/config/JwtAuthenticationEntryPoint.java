package org.example.jwt_token.config;

import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Handles unauthorized access attempts by returning a structured JSON 401 response.
 * Triggered when an unauthenticated request hits a protected route.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    /**
     * Called when authentication fails or is missing on a protected endpoint.
     * Writes a JSON error body with status 401 instead of Spring's default HTML error page.
     *
     * @param request       the request that caused the exception
     * @param response      the response to write the 401 error to
     * @param authException the exception that triggered this entry point
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", 401);
        body.put("error", "Unauthorized");
        body.put("message", "Access Denied");
        body.put("path", request.getRequestURI());

        objectMapper.writeValue(response.getWriter(), body);
    }
}
