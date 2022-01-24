package com.example.utubeclone.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@Setter
@AllArgsConstructor
public class LoginRequest {
    @NotBlank
    @Size(max = 50)
    private String username;
    @NotBlank
    private String password;
}
