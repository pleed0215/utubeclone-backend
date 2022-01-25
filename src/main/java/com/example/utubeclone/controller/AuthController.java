package com.example.utubeclone.controller;

import com.example.utubeclone.auth.JwtUtils;
import com.example.utubeclone.auth.UserDetailsImpl;
import com.example.utubeclone.auth.dto.JwtResponse;
import com.example.utubeclone.auth.dto.LoginRequest;
import com.example.utubeclone.auth.dto.SignupRequest;
import com.example.utubeclone.auth.exception.EmailAlreadyExistsException;
import com.example.utubeclone.auth.exception.UsernameAlreadyExistException;
import com.example.utubeclone.core.dto.MessageResponse;
import com.example.utubeclone.models.AuthRole;
import com.example.utubeclone.models.RoleName;
import com.example.utubeclone.models.User;
import com.example.utubeclone.repository.AuthRoleRepository;
import com.example.utubeclone.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@Slf4j
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final AuthRoleRepository roleRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserRepository userRepository, AuthRoleRepository roleRepository, JwtUtils jwtUtils, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/signin")
public ResponseEntity<?> authenticateUser(@Validated @RequestBody LoginRequest loginRequest, SecurityContextHolderAwareRequestWrapper request) throws Exception {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        request.getSession().setAttribute("loggedIn", true);

        log.info("Signin request: " +request.getSession().getAttribute("loggedIn"));

        return ResponseEntity.ok(
                JwtResponse.builder()
                        .id(userDetails.getId())
                        .username(userDetails.getUsername())
                        .email(userDetails.getEmail())
                        .token(jwt)
                        .roles(roles)
                        .build()
        );
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Validated @RequestBody SignupRequest signupRequest) throws Exception {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            throw new UsernameAlreadyExistException("Username already exists. Try another.");
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new EmailAlreadyExistsException("Username already exists. Try another.");
        }

        User user = new User(
                signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword())
        );
        Set<String> strRoles = signupRequest.getRoles();
        Set<AuthRole> roles = new HashSet<>();
        if(strRoles == null || strRoles.size() == 0) {
            AuthRole role = roleRepository.findByName(RoleName.ROLE_USER)
                    .orElseThrow( () -> new RuntimeException("Error: role is not found"));
            roles.add(role);
        } else {
            strRoles.forEach(role -> {
                switch(role) {
                    case "admin":
                        AuthRole adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
                                .orElseThrow( () -> new RuntimeException("Error: role is not found"));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        AuthRole modRole = roleRepository.findByName(RoleName.ROLE_MODERATOR)
                                .orElseThrow( () -> new RuntimeException("Error: role is not found"));
                        roles.add(modRole);
                        break;
                    default:
                        AuthRole userRole = roleRepository.findByName(RoleName.ROLE_USER)
                                .orElseThrow( () -> new RuntimeException("Error: role is not found"));
                        roles.add(userRole);
                        break;
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(
                new MessageResponse(
                        "User register success",
                        HttpStatus.OK.value()
                )
        );
    }
}
