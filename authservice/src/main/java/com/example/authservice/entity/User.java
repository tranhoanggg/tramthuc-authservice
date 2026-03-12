package com.example.authservice.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String fullName;

    @Column(nullable = false)
    private LocalDate dob; 

    @Column(nullable = false)
    private String gender; 

    @Column(unique = true)
    private String email; 

    @Column(unique = true)
    private String phoneNumber; 

    @Column
    private String password;

    @Column(nullable = false)
    private String role; 
    
    @Column(nullable = false)
    private String authProvider; 

    public String getPrimaryIdentifier() {
        return (email != null && !email.isEmpty()) ? email : phoneNumber;
    }
}