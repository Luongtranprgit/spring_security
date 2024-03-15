package com.jwtsample.jwt.service;

import com.jwtsample.jwt.controller.PublicApiController;
import com.jwtsample.jwt.model.User;
import com.jwtsample.jwt.repository.UserRepository;
import com.jwtsample.jwt.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtils;
    private final UserRepository repository;

    public String loginAndGenerateToken(PublicApiController.LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));

        return jwtUtils.createToken(authentication);
    }

    public void createUser(User user) {
        //verify if username already exists
        repository.findByUsername(user.getUsername()).ifPresent(u -> {
            throw new RuntimeException("Username already exists");
        });
        repository.save(user);
    }

    public boolean userExists(String username) {
        return repository.findByUsername(username).isPresent();
    }
}