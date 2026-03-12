package com.example.authservice.dto;
import lombok.Data;

@Data
public class VerifyRequest {
    private String identifier; // Send to email or phone number
}