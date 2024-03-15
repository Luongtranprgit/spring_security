package com.jwtsample.jwt.utils;


import java.util.List;

import com.jwtsample.jwt.model.User;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.jwtsample.jwt.service.UserService;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitScript {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationEvent() {
        log.info("Application is ready");

        if (userService.userExists("admin")) {
            log.info("Admin already exists");
            return;
        }
        var admin = new User();
        admin.setUsername("admin12");
        admin.setPassword(passwordEncoder.encode("admin12"));
        admin.setRoles(List.of("ADMIN"));
        userService.createUser(admin);

        var user = new User();
        user.setUsername("member");
        user.setPassword(passwordEncoder.encode("member"));
        user.setRoles(List.of("MEMBER"));
        userService.createUser(user);

    }
}