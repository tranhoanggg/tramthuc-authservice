package com.example.authservice.security;

import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // 1. Tắt CSRF (Bắt buộc khi làm REST API dùng Token)
            .csrf(AbstractHttpConfigurer::disable)
            
            // 2. Cấu hình phân quyền các đường dẫn (URL)
            .authorizeHttpRequests(auth -> auth
                // Cho phép truy cập tự do vào các API Đăng ký/Đăng nhập và các file giao diện tĩnh (HTML/CSS/JS)
                .requestMatchers(
                    "/api/auth/**", 
                    "/error",
                    "/login.html", 
                    "/register.html", 
                    "/", 
                    "/css/**", 
                    "/js/**"
                ).permitAll()
                // Tất cả các request khác (ví dụ: /api/user/profile) đều bắt buộc phải có Token hợp lệ
                .anyRequest().authenticated()
            )
            
            // 3. Không sử dụng Session mặc định của Spring (Vì chúng ta dùng JWT)
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // 4. Khai báo AuthenticationProvider (Cung cấp UserDetailsService và PasswordEncoder)
            .authenticationProvider(authenticationProvider())
            
            // 5. Chèn bộ lọc kiểm tra JWT của chúng ta vào TRƯỚC bộ lọc đăng nhập mặc định của Spring
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // QUY ĐỊNH LUẬT CORS
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Cho phép Frontend ở localhost:3000 và Vercel (nếu có sau này) gọi vào
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://tramthuc.vercel.app")); 
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true); // Cho phép gửi cookie/token
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Áp dụng cho mọi API
        return source;
    }

    // Cấu hình thuật toán mã hóa mật khẩu cực mạnh: BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

// Nối UserDetailsService và PasswordEncoder lại với nhau
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // 1. Truyền thẳng userDetailsService vào trong ngoặc tròn
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        
        // 2. Chỉ cần set PasswordEncoder nữa là xong (xóa dòng setUserDetailsService cũ đi)
        authProvider.setPasswordEncoder(passwordEncoder());
        
        return authProvider;
    }

    // Lấy ra AuthenticationManager để dùng trong Controller khi xử lý đăng nhập
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}