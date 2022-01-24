package com.example.utubeclone.auth.dto;

import lombok.Getter;
import lombok.Setter;


import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.*;

@Getter
@Setter
public class SignupRequest{
    @NotBlank
    @Size(min=4, max = 50, message="Username length must be between 4 and 50")
    private String username;
    @NotBlank
    @Size(min=8, max=24)
    private String password;
    @NotBlank
    @Email
    private String email;

    private List<String> roles;


    public SignupRequest(String username, String password, String email, List<String> roles) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.roles = roles == null ? new ArrayList<>() : roles;
    }

    public Set<String> getRoles() {
        return new HashSet<>(roles);
    }
}
