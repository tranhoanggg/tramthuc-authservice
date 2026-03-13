package com.example.authservice.dto;
import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String identifier; 
    private String otp;        
    private String newPassword;
}