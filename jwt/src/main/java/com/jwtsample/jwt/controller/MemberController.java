package com.jwtsample.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/member")

public class MemberController {
    @GetMapping("/hello")
    public String hello(){
        return "Hello Member";
    }
}
