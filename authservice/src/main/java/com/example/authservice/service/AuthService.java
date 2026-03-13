package com.example.authservice.service;

import com.example.authservice.dto.*;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.security.JwtUtil;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;
    
    // TIÊM CÔNG CỤ GỬI EMAIL VÀO ĐÂY
    private final JavaMailSender mailSender;

    // 1. KHAI BÁO BỘ LỌC REGEX CHUẨN MỰC
    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$";
    private static final String PHONE_REGEX = "^(0[3|5|7|8|9])+([0-9]{8})$";

    public Map<String, Boolean> verifyIdentity(String identifier) {
        boolean exists = userRepository.findByEmailOrPhoneNumber(identifier, identifier).isPresent();
        return Map.of("exists", exists);
    }

    // 2. CẬP NHẬT HÀM GỬI OTP (CÓ REGEX & EMAIL THẬT)
    public String sendOtp(String identifier) {
        // Sinh ngẫu nhiên mã OTP 6 số
        String otp = String.format("%06d", new java.util.Random().nextInt(999999));

        if (Pattern.matches(EMAIL_REGEX, identifier)) {
            // NẾU LÀ EMAIL CHUẨN -> GỬI EMAIL THẬT
            sendEmailOtp(identifier, otp);
        } else if (Pattern.matches(PHONE_REGEX, identifier)) {
            // NẾU LÀ SĐT CHUẨN -> TẠM THỜI GIẢ LẬP
            System.out.println("========== [SMS GIẢ LẬP] GỬI ĐẾN " + identifier + " | MÃ OTP: " + otp + " ==========");
        } else {
            // NẾU NHẬP LINH TINH -> CHẶN NGAY!
            throw new RuntimeException("Lỗi: Định dạng Email hoặc Số điện thoại không hợp lệ!");
        }

        // Lưu vào Redis, sống trong 3 phút
        redisTemplate.opsForValue().set("OTP:" + identifier, otp, 3, TimeUnit.MINUTES);

        return "Mã xác nhận đã được gửi thành công!";
    }

    // 3. HÀM PHỤ TRỢ: SOẠN VÀ GỬI EMAIL HTML
    private void sendEmailOtp(String toEmail, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(toEmail);
            helper.setSubject("[Trạm Thức] Mã xác nhận đăng ký tài khoản");

            // Soạn một bức thư HTML đẹp mắt
            String htmlContent = "<div style='font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;'>"
                    + "<h2 style='color: #c17a54; text-align: center;'>Chào mừng bạn đến với Trạm Thức!</h2>"
                    + "<p>Bạn đang thực hiện đăng ký tài khoản mới. Vui lòng sử dụng mã xác nhận bên dưới để hoàn tất quá trình đăng ký:</p>"
                    + "<div style='text-align: center; margin: 30px 0;'>"
                    + "<span style='font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0f83c9; background: #f5f5f5; padding: 10px 20px; border-radius: 8px;'>" + otp + "</span>"
                    + "</div>"
                    + "<p>Mã này sẽ hết hạn sau <strong>3 phút</strong>. Tuyệt đối không chia sẻ mã này cho bất kỳ ai.</p>"
                    + "<p style='margin-top: 40px; font-size: 12px; color: #888; text-align: center;'>Nếu bạn không yêu cầu mã này, vui lòng bỏ qua email.</p>"
                    + "</div>";

            helper.setText(htmlContent, true); // true = Bật chế độ HTML
            mailSender.send(message);

        } catch (Exception e) {
            System.err.println("Lỗi khi gửi email: " + e.getMessage());
            throw new RuntimeException("Không thể gửi email lúc này. Vui lòng thử lại sau!");
        }
    }

    // 4. HÀM ĐĂNG KÝ (ĐÃ FIX LỖI DUPLICATE ENTRY CHO CHUỖI RỖNG)
    public String register(RegisterRequest request) {
        if (request.getEmail() != null && !request.getEmail().isEmpty() && userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Lỗi: Email này đã được sử dụng!");
        }
        if (request.getPhoneNumber() != null && !request.getPhoneNumber().isEmpty() && userRepository.existsByPhoneNumber(request.getPhoneNumber())) {
            throw new RuntimeException("Lỗi: Số điện thoại này đã được sử dụng!");
        }

        String encodedPassword = (request.getPassword() != null && !request.getPassword().isEmpty()) 
                ? passwordEncoder.encode(request.getPassword()) 
                : null;

        // BƯỚC QUAN TRỌNG: Chuẩn hoá chuỗi rỗng ("") thành null để MySQL/TiDB không bị lỗi Unique Constraint
        String validEmail = (request.getEmail() != null && !request.getEmail().trim().isEmpty()) ? request.getEmail().trim() : null;
        String validPhone = (request.getPhoneNumber() != null && !request.getPhoneNumber().trim().isEmpty()) ? request.getPhoneNumber().trim() : null;

        User user = User.builder()
                .fullName(request.getFullName())
                .dob(request.getDob()) 
                .gender(request.getGender())
                .email(validEmail)       // Dùng biến đã chuẩn hoá
                .phoneNumber(validPhone) // Dùng biến đã chuẩn hoá
                .password(encodedPassword)
                .role("ROLE_USER") 
                .authProvider("LOCAL") 
                .build();

        userRepository.save(user);
        
        // Xóa OTP khỏi Redis
        if (request.getPhoneNumber() != null && !request.getPhoneNumber().isEmpty()) {
            redisTemplate.delete("OTP:" + request.getPhoneNumber());
        }
        if (request.getEmail() != null && !request.getEmail().isEmpty()) {
            redisTemplate.delete("OTP:" + request.getEmail());
        }
        
        return "Đăng ký thành công!";
    }

    public AuthResponse loginWithOtp(LoginOtpRequest request) {
        String savedOtp = redisTemplate.opsForValue().get("OTP:" + request.getIdentifier());
        if (savedOtp == null || !savedOtp.equals(request.getOtp())) {
            throw new RuntimeException("Lỗi: Mã OTP không chính xác hoặc đã hết hạn!");
        }
        User user = userRepository.findByEmailOrPhoneNumber(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new RuntimeException("Người dùng không tồn tại!"));
        redisTemplate.delete("OTP:" + request.getIdentifier());
        String token = jwtUtil.generateToken(user.getPrimaryIdentifier()); 
        return new AuthResponse(token);
    }

    public AuthResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getIdentifier(), request.getPassword())
        );
        User user = userRepository.findByEmailOrPhoneNumber(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new RuntimeException("Lỗi xác thực"));
        String token = jwtUtil.generateToken(user.getEmail());
        return new AuthResponse(token);
    }

    public String logout(String token) {
        Date expirationDate = jwtUtil.extractExpiration(token);
        long remainingTime = expirationDate.getTime() - System.currentTimeMillis();
        if (remainingTime > 0) {
            redisTemplate.opsForValue().set("BLACKLIST:" + token, "true", remainingTime, TimeUnit.MILLISECONDS);
        }
        return "Đăng xuất thành công!";
    }

    public AuthResponse googleLogin(GoogleLoginRequest request) {
        RestTemplate restTemplate = new RestTemplate();
        String googleApiUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=" + request.getIdToken();
        try {
            Map<String, Object> payload = restTemplate.getForObject(googleApiUrl, Map.class);
            if (payload == null || !payload.containsKey("email")) {
                throw new RuntimeException("Token Google không hợp lệ hoặc đã hết hạn!");
            }
            
            String email = (String) payload.get("email");
            String name = (String) payload.get("name");
            User user = userRepository.findByEmail(email).orElse(null);
            
            if (user == null) {
                throw new RuntimeException("GOOGLE_NOT_REGISTERED|" + email + "|" + (name != null ? name : ""));
            }
            
            String token = jwtUtil.generateToken(user.getEmail());
            return new AuthResponse(token);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}