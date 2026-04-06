package org.example.jwt_token.role;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    USER,
    ADMIN;

    @Override
    public String getAuthority() {
        return "ROLE_" + this.name(); // → "ROLE_USER", "ROLE_ADMIN"
    }

    }

