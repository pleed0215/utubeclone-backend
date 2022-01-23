package com.example.utubeclone.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
public class SignupRequest extends LoginRequest{
    private String email;

    public SignupRequest(String username, String password, String email) {
        super(username, password);
        this.email = email;
    }
}
