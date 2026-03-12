package com.example.authservice.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    private final StringRedisTemplate redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Lấy header có tên "Authorization" từ request gửi lên
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        // 2. Nếu không có header hoặc header không bắt đầu bằng chữ "Bearer " -> Bỏ qua, cho đi tiếp tới bộ lọc khác
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Cắt bỏ chữ "Bearer " (7 ký tự) để lấy cái Token nguyên bản
        jwt = authHeader.substring(7);
        
        Boolean isBlacklisted = redisTemplate.hasKey("BLACKLIST:" + jwt);
        if (Boolean.TRUE.equals(isBlacklisted)) {
            // Nếu có trong sổ đen, chặn lại ngay lập tức và báo lỗi 401
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Token nay da bi thu hoi (Dang xuat). Vui long dang nhap lai!");
            return;
        }

        username = jwtUtil.extractUsername(jwt);

        // 4. Nếu có username và SecurityContext chưa ghi nhận người này đăng nhập
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            
            // Lấy thông tin chi tiết của người dùng từ Database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // 5. Nếu Token hợp lệ, hợp pháp hóa phiên đăng nhập này
            if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                
                // Cập nhật thẻ căn cước vào SecurityContextHolder (Hệ thống ghi nhận đã đăng nhập thành công)
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        // 6. Cho phép request đi tiếp vào Controller (API)
        filterChain.doFilter(request, response);
    }
}