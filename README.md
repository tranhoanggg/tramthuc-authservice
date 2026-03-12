# 🔐 Auth Service - Trạm Thức (Identity Provider)

Dự án này đóng vai trò là một **Hệ thống Xác thực Trung tâm (Identity Provider - IdP)** cung cấp giải pháp **Unified Authentication (Xác thực hợp nhất)** cho hệ sinh thái website Trạm Thức (bao gồm Frontend NextJS và Backend Resource ExpressJS). 

Được xây dựng bằng **Java Spring Boot**, dự án cung cấp hệ thống quản lý định danh người dùng mạnh mẽ, hỗ trợ đăng nhập đa hình (Email/Phone, Mật khẩu, OTP, Google OAuth2) và kết nối với cơ sở dữ liệu phân tán **TiDB** cùng bộ nhớ đệm tốc độ cao **Redis Cloud**.

Chúng ta sẽ cùng tìm hiểu qua từng phần:

1. Kiến trức bảo mật (Security Architecture)
2. Vai trò của Redis
3. Nền tảng ảo hoá Docker
4. Triển khai Redis trên Docker

---

## 🛡️ 1. Kiến trúc Bảo mật (Security Architecture)

Hệ thống bảo mật của dự án được thiết kế theo tiêu chuẩn kiến trúc **Stateless (Phi trạng thái)** chuyên dụng cho Microservices, đảm bảo khả năng mở rộng (scale) không giới hạn mà vẫn bảo mật tuyệt đối.

### 🎟️ A. Trái tim của hệ thống: JWT (JSON Web Token)
Thay vì sử dụng cơ chế Session/Cookie truyền thống lưu trữ trạng thái tại Server, hệ thống sử dụng Token.
- Khi người dùng xác thực thành công, `JwtUtil` sẽ sản xuất một chiếc "vé thông hành" (JWT) được ký bằng thuật toán `HS256` cùng một Khóa bí mật (Secret Key) siêu mạnh.
- Khóa này chứa định danh của người dùng (`identifier`: email hoặc số điện thoại) và có vòng đời sử dụng độc lập (ví dụ: 1 ngày). Frontend (NextJS) sẽ chịu trách nhiệm cất giữ vé này để xuất trình cho các lần gọi API tiếp theo.

### 👮‍♂️ B. Người gác cổng: `JwtAuthFilter` & `SecurityConfig`
Mọi lưu lượng dữ liệu (Traffic) đi vào hệ thống đều phải lọt qua sự kiểm soát nghiêm ngặt của mạng lưới Spring Security:
- **Thiết quân luật (`SecurityConfig`)**: 
  - Vô hiệu hóa bảo vệ CSRF (mặc định không cần thiết đối với kiến trúc REST API Stateless).
  - Phân quyền định tuyến (Routing): Mở cửa tự do (`permitAll`) cho các API xác thực ban đầu (`/api/auth/**`), yêu cầu xác thực (`authenticated`) đối với toàn bộ các API còn lại.
  - **CORS Policy**: Giới hạn nghiêm ngặt nguồn gốc truy cập. Chỉ cho phép các domain hợp lệ như `http://localhost:3000` (môi trường dev) và `https://tramthuc.vercel.app` (môi trường production) được phép giao tiếp và đính kèm Credentials.
- **Trạm kiểm tra (`JwtAuthFilter`)**: Là bộ lọc (Filter) đứng ngay cửa ngõ. Nó bóc tách Header `Authorization`, rút lấy Token, kiểm tra tính toàn vẹn của chữ ký, kiểm tra thời hạn trước khi hợp pháp hóa phiên đăng nhập để chuyển tới Controller.

### 📕 C. Thu hồi Token với Sổ đen Redis (Blacklist)
Đặc thù của JWT là không thể bị hủy ngang (revoke) từ phía Server trước khi tự hết hạn. Hệ thống giải quyết nhược điểm này một cách khéo léo bằng **Redis Cloud**:
- **Luồng Đăng xuất (Logout)**: Khi người dùng đăng xuất, API `/logout` sẽ tính toán chính xác *thời gian sống còn lại* của Token đó và đẩy nó vào Redis kèm theo tiền tố `BLACKLIST:`.
- **Tối ưu hóa RAM**: Redis được setup cơ chế TTL (Time-to-live) cho các khóa Blacklist này bằng đúng thời gian sống còn lại của Token, giúp dọn dẹp bộ nhớ tự động.
- Trạm gác `JwtAuthFilter` luôn chọc vào Redis để tra cứu Sổ đen trước khi cho qua. Nếu phát hiện Token đã bị thu hồi, hệ thống lập tức chối bỏ quyền truy cập (Lỗi 401 Unauthorized).

### 🌍 D. Xác thực Đa định danh (Unified Auth) & OAuth2
Hệ thống thoát khỏi lối mòn `username/password` thông thường để tiến tới hệ thống IdP hiện đại:
- **Đăng nhập linh hoạt**: `CustomUserDetailsService` kết hợp với `UserRepository` cho phép tìm kiếm người dùng bằng cả Email hoặc Số điện thoại.
- **Đăng nhập không mật khẩu (OTP)**: Tích hợp luồng gửi và xác minh mã OTP một lần (Sử dụng Redis làm nơi lưu trữ OTP tạm thời với TTL ngắn).
- **Google Social Login**: Xử lý `id_token` do Frontend gửi lên. Server không tin tưởng một cách mù quáng mà tự động tạo các request HTTP nội bộ lên máy chủ Google (`oauth2.googleapis.com`) để Verify chữ ký, bảo vệ hệ thống khỏi các Token giả mạo.

### 🔐 E. Bảo mật dữ liệu tĩnh
- **Băm một chiều (Hashing)**: Không có mật khẩu thô nào tồn tại trong Database. Mọi mật khẩu được đi qua máy xay `BCryptPasswordEncoder`. Ngay cả người quản trị Database cũng không thể đọc được mật khẩu của người dùng.
- **Che giấu Biến môi trường**: Mọi thông tin nhạy cảm (URL kết nối TiDB, Password Database, Redis Cloud Host, JWT Secret Key) hoàn toàn vắng mặt trong mã nguồn (được tiêm qua các biến `${DB_USERNAME}`, `${REDIS_HOST}`). Mã nguồn an toàn 100% khi Public (mở mã nguồn) trên GitHub.

---

## 🚀 2. Vai trò của Redis (Bộ nhớ đệm & Quản lý trạng thái tạm thời)

Trong một kiến trúc Microservices thuần Stateless, việc quản lý các dữ liệu "phù du" (chỉ tồn tại trong một khoảng thời gian ngắn) bằng Database chính (như TiDB/MySQL) là không tối ưu do tốc độ đọc/ghi vào ổ cứng chậm. Do đó, hệ thống tích hợp **Redis Cloud** (Cơ sở dữ liệu In-Memory) để giải quyết triệt để 2 bài toán hóc búa sau:

### 🛑 A. Giải quyết "Tử huyệt" của JWT (Token Revocation/Blacklist)
Khác với Session lưu trên máy chủ, JWT sau khi phát hành sẽ tự trị. Server không có cách nào "rút" lại vé này nếu người dùng bấm đăng xuất hoặc bị lộ Token, dẫn đến rủi ro bảo mật lớn. 

**Cách Redis giải quyết:**
1. **Đưa vào Sổ đen (Blacklisting)**: Khi API `/api/auth/logout` được gọi, hệ thống sẽ trích xuất Token hiện tại và lưu vào Redis với Key là `BLACKLIST:<token>`.
2. **Đồng bộ hóa TTL (Time-to-Live)**: Đây là kỹ thuật tối ưu RAM tuyệt đối. Hệ thống sẽ tính toán chính xác *thời gian sống còn lại* của JWT và set đúng mức thời gian đó làm TTL cho record trong Redis. 
   - *Ví dụ:* Token có hạn 24h, user dùng được 10h rồi bấm đăng xuất. Token này sẽ nằm trong Redis chính xác 14h nữa rồi tự động bốc hơi.
3. **Chặn đứng truy cập**: Bộ lọc `JwtAuthFilter` ở cửa ngõ sẽ luôn Query vào Redis trong vòng 1-2 mili-giây. Nếu Key tồn tại, Request lập tức bị từ chối (401 Unauthorized).

### 🔑 B. Quản lý Vòng đời Mã xác thực (OTP Management)
Đối với tính năng Đăng nhập không mật khẩu (Passwordless) hoặc Xác minh định danh, việc lưu mã OTP vào Database chính là sự lãng phí tài nguyên không cần thiết.

**Cách Redis tối ưu hóa luồng OTP:**
1. **Lưu trữ tốc độ cao**: Khi gọi API `/api/auth/send-otp`, một mã 6 chữ số ngẫu nhiên được sinh ra và lưu thẳng vào Redis với Key theo định dạng `OTP:<identifier>` (identifier là Email hoặc Số điện thoại).
2. **Tự động hủy (Auto-expiration)**: Hệ thống cấu hình TTL cho mọi mã OTP chỉ kéo dài **3 phút**. Hết 3 phút, mã tự động biến mất khỏi bộ nhớ mà không cần viết bất kỳ tác vụ (Cronjob) dọn dẹp nào.
3. **Xác thực 1 lần (One-Time use)**: Khi API `/api/auth/login-otp` nhận được yêu cầu, nó sẽ đối chiếu mã. Nếu trùng khớp, Token sẽ được cấp và **Key OTP đó sẽ bị xóa ngay lập tức** khỏi Redis bằng lệnh `redisTemplate.delete()`, đảm bảo mã không bao giờ được sử dụng lại lần thứ hai.

---

## 🐳 3. Nền tảng Ảo hóa Docker (Local Development Environment)

Để đảm bảo tính đồng nhất giữa các môi trường (Dev, Test, Production) và loại bỏ hoàn toàn căn bệnh kinh điển "Code chạy trên máy tôi nhưng lỗi trên máy khác", dự án sử dụng **Docker** và **Docker Compose** làm nền tảng đóng gói cơ sở hạ tầng.

Thay vì phải cài đặt thủ công từng phần mềm cơ sở dữ liệu lên máy tính cá nhân (dễ gây xung đột và rác hệ thống), toàn bộ hạ tầng phụ trợ (Dependencies) được "đóng gói" thành các Container độc lập:

### 🗄️ A. Database Container (MySQL 8.0)
Mặc dù trên môi trường Cloud, dự án sử dụng **TiDB** làm database chính, nhưng ở môi trường Local (máy phát triển), chúng ta sử dụng một Container MySQL 8.0 để mô phỏng.
- **Xử lý xung đột cổng (Port Mapping)**: Container được thiết lập khéo léo để ánh xạ cổng `3306` bên trong ra cổng `3307` của máy Host (`"3307:3306"`). Điều này giúp MySQL trong Docker chạy song song mượt mà, không hề "đụng độ" với bất kỳ phần mềm XAMPP, WAMP hay MySQL Workbench nào đã cài sẵn trên máy của lập trình viên.
- **Tự động hóa (Auto-provisioning)**: Mọi thông số như `MYSQL_ROOT_PASSWORD` hay `MYSQL_DATABASE` đều được tự động khởi tạo ngay khi Container nhấc mình lên.

### ⚡ B. Cache Container (Redis Alpine)
Phiên bản siêu nhẹ `redis:alpine` được sử dụng để cung cấp sức mạnh quản lý Token Blacklist và OTP mà không "ăn" quá nhiều RAM của máy tính phát triển.
- Chạy ở cổng tiêu chuẩn `6379`.
- Sẵn sàng đón nhận hàng ngàn request đọc/ghi mỗi giây từ Spring Boot.

### 👆🏻 C. Trải nghiệm "One-Click Setup"
Nhờ file `docker-compose.yml`, bất kỳ lập trình viên nào mới tham gia dự án cũng không cần đọc tài liệu cài đặt dài dòng. Toàn bộ cơ sở hạ tầng tốn hàng giờ setup giờ đây được thu gọn lại trong đúng **một câu lệnh duy nhất**:
```bash
docker-compose up -d
