package com.example.authservice.controller;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.GoogleLoginRequest;
import com.example.authservice.dto.LoginOtpRequest;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.dto.VerifyRequest;
import com.example.authservice.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // API Đăng ký: POST http://localhost:8080/api/auth/register
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        try {
            return ResponseEntity.ok(authService.register(request));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // API Đăng nhập: POST http://localhost:8080/api/auth/login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            return ResponseEntity.ok(authService.logout(token));
        }
        return ResponseEntity.badRequest().body("Yêu cầu không hợp lệ!");
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyIdentity(@RequestBody VerifyRequest request) {
        try {
            return ResponseEntity.ok(authService.verifyIdentity(request.getIdentifier()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/send-otp")
    public ResponseEntity<String> sendOtp(@RequestBody VerifyRequest request) {
        try {
            return ResponseEntity.ok(authService.sendOtp(request.getIdentifier()));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestBody GoogleLoginRequest request) { // SỬA: Thay <AuthResponse> thành <?>
        try {
            return ResponseEntity.ok(authService.googleLogin(request));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login-otp")
    public ResponseEntity<AuthResponse> loginWithOtp(@RequestBody LoginOtpRequest request) {
        try {
            return ResponseEntity.ok(authService.loginWithOtp(request));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().build();
        }
    }
}