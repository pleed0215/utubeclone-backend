package com.example.utubeclone.auth.dto;

import lombok.*;

import java.util.List;

@Builder
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String token;
    private String id;
    private String type;
    private String username;
    private String email;
    private List<String> roles;
}
