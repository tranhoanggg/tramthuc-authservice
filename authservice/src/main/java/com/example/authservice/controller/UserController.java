package com.example.authservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/user")
public class UserController {

    // API này đã được SecurityConfig bảo vệ ngầm. 
    // Chỉ những ai gửi kèm Token hợp lệ mới vào được đây.
    @GetMapping("/profile")
    public ResponseEntity<String> getProfile(Principal principal) {
        // principal.getName() sẽ tự động lấy ra username từ trong Token
        return ResponseEntity.ok("Xin chào " + principal.getName() + "! Chào mừng bạn đến với khu vực an toàn.");
    }
}