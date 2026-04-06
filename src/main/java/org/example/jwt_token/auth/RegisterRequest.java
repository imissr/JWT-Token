package com.example.app.auth;


import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
public class RegisterRequest {

    @NonNull
    private String username;
    @NonNull
    private String password;
}