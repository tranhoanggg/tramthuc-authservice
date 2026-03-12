package com.example.authservice.dto;

import java.time.LocalDate;

import lombok.Data;

@Data
public class RegisterRequest {
    private String fullName;
    private LocalDate dob; 
    private String gender; 
    private String email; 
    private String phoneNumber; 
    private String password;
    private String otp;
}