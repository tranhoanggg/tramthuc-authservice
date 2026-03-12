package com.example.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    // Đây là "Chìa khóa bí mật" để ký Token. TUYỆT ĐỐI không để lộ mã này ra ngoài.
    // Mã này là một chuỗi ngẫu nhiên dài 256-bit được mã hóa Base64
    @Value("${jwt.secret.key}")
    private String SECRET_KEY;

    // Thời gian sống của Token: 1 ngày (tính bằng mili-giây)
    private static final long TOKEN_VALIDITY = 1000 * 60 * 60 * 24;

    // 1. Lấy ra "chìa khóa" đã được giải mã để sử dụng
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // 2. Hàm tạo ra Token khi người dùng đăng nhập thành công
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username) // Subject chính là tên người dùng
                .setIssuedAt(new Date(System.currentTimeMillis())) // Thời điểm tạo
                .setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY)) // Thời điểm hết hạn
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Ký bằng thuật toán HS256
                .compact();
    }

    // 3. Hàm trích xuất Username từ một cái Token do Client gửi lên
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // 4. Hàm trích xuất ngày hết hạn của Token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 5. Hàm kiểm tra xem Token đã hết hạn chưa
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // 6. Hàm kiểm tra tổng thể Token có hợp lệ với Username không
    public Boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(username) && !isTokenExpired(token));
    }
}