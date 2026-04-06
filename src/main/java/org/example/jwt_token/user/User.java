package org.example.jwt_token.user;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.*;
import org.example.jwt_token.role.Role;
import org.jspecify.annotations.Nullable;

/**
 * JPA entity representing a user in the system.
 * Stored in the database and used for authentication and authorization.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    /** Auto-generated primary key using a database sequence. */
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private long id;

    private String name;

    /** Unique identifier used for login. Stored in lowercase. */
    private String username;

    /** BCrypt-hashed password. Never stored as plain text. */
    private String passowrd;

    /** The role assigned to this user (e.g. USER, ADMIN), used for authorization. */
    private Role role;
}
