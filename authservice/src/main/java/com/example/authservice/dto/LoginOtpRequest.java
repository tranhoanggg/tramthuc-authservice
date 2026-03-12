package com.example.authservice.dto;
import lombok.Data;

@Data
public class LoginOtpRequest {
    private String identifier; // Email or phone number
    private String otp;
}