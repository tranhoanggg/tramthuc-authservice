package com.example.authservice.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String identifier; // Email or phone
    private String password;
}