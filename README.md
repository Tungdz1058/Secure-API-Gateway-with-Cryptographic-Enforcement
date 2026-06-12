
```bash
cat > ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement/README.md << 'EOF'
# Secure API Gateway with Cryptographic Enforcement

## 📌 Mô tả đồ án

Đồ án triển khai **API Gateway an toàn** với các cơ chế mật mã:
- **OAuth2 / OpenID Connect** (PKCE) - Xác thực người dùng qua Keycloak
- **JWT** (RS256) - Token-based authentication/authorization
- **HMAC request signing** - Đảm bảo tính toàn vẹn và chống replay
- **Redis** - Lưu nonce để chống tấn công replay
- **Kong Gateway** - Reverse proxy (forward request)

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Website   │────▶│     Kong    │────▶│   Backend   │────▶│   Redis     │
│   (SPA)     │     │  (Gateway)  │     │  (FastAPI)  │     │  (Nonce)    │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                    │                    │
       ▼                   ▼                    ▼                    ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Keycloak   │     │   JWT       │     │   HMAC      │     │   User      │
│   (IdP)     │     │  Verify     │     │  Verify     │     │   Info      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

## 🛠️ Công nghệ sử dụng

| Thành phần | Công nghệ | Vai trò |
|------------|-----------|---------|
| **Identity Provider** | Keycloak 22.0 | Cấp JWT token, quản lý danh tính |
| **API Gateway** | Kong 3.7 | Reverse proxy (forward request) |
| **Backend** | FastAPI (Python) | Xác thực JWT, HMAC, nonce |
| **Nonce Store** | Redis | Lưu nonce đã dùng, chống replay |
| **Website** | HTML/JS (SPA) | OAuth2 PKCE, gọi API |

---

## 📋 Yêu cầu hệ thống

- **Ubuntu 22.04 / 24.04** (hoặc WSL2 trên Windows)
- **Docker** và **Docker Compose**
- **Python 3.10+**
- **Git**

---

## 🚀 Hướng dẫn cài đặt và chạy (cho các thành viên trong nhóm)

### 1️⃣ Clone repository

```bash
git clone git@github.com:Tungdz1058/Secure-API-Gateway-with-Cryptographic-Enforcement.git
cd Secure-API-Gateway-with-Cryptographic-Enforcement
```

### 2️⃣ Tạo và kích hoạt môi trường ảo Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3️⃣ Khởi động các container (Keycloak, PostgreSQL, Kong)

```bash
cd infra
docker compose -f docker-compose.yml -f docker-compose.kong.yml up -d
```

### 4️⃣ Khởi động Redis (lưu nonce)

```bash
docker run -d --name redis -p 6379:6379 redis
# Hoặc nếu đã có container cũ:
docker start redis
```

### 5️⃣ Kiểm tra các container đã chạy

```bash
docker ps
```

Bạn sẽ thấy:
- `infra-postgres-1` (PostgreSQL)
- `infra-keycloak-1` (Keycloak, cổng 8080)
- `infra-kong-1` (Kong, cổng 8000)
- `redis` (Redis, cổng 6379)

### 6️⃣ Cấu hình Keycloak

Truy cập: `http://localhost:8080`

- **Username:** `admin`
- **Password:** `admin`

#### Tạo Realm `api-gateway-demo`
- Nhấn **Create realm**
- **Name:** `api-gateway-demo`
- Nhấn **Create**

#### Tạo Client `api-spa` (public client)
- Vào **Clients** → **Create client**
- **Client ID:** `api-spa`
- **Capability config:**
  - Client authentication: `OFF`
  - Standard flow: `ON`
- **Login settings:**
  - Valid redirect URIs: `http://localhost:3000/*`
  - Web origins: `http://localhost:3000`
- Nhấn **Save**

#### Tạo User `demo`
- Vào **Users** → **Create new user**
- **Username:** `demo`
- **Email:** `demo@example.com`
- **Email verified:** `ON`
- Nhấn **Create**
- Vào tab **Credentials** → **Set password**
- **Password:** `demo123`
- **Temporary:** `OFF`
- Nhấn **Set password**

### 7️⃣ Khởi động Backend (FastAPI)

Mở **Terminal mới**:

```bash
cd ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement
source venv/bin/activate
python services/backend.py
```

Giữ terminal này chạy. Bạn sẽ thấy dòng:
```
[OK] Redis connected
INFO:     Uvicorn running on http://0.0.0.0:5000
```

### 8️⃣ Khởi động Website (SPA)

Mở **Terminal mới**:

```bash
cd ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement/clients/spa
python3 -m http.server 3000
```

### 9️⃣ Truy cập website

Mở trình duyệt: `http://localhost:3000`

#### Đăng nhập
- Nhấn nút **Login with Keycloak (PKCE)**
- Chuyển hướng đến Keycloak
- Đăng nhập với `demo` / `demo123`
- Đồng ý cấp quyền
- Redirect về website, hiển thị token và thông tin user

#### Gọi API
- Nhấn nút **Call API**
- Kết quả hiển thị:
```json
{
  "message": "API called successfully",
  "jwt_verified": true,
  "hmac_verified": false,
  "user": "demo",
  "email": "demo@gmail.com"
}
```

### 🔟 Kiểm tra HMAC signing (client Python)

Mở **Terminal mới**:

```bash
cd ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement
source venv/bin/activate
python clients/hmac_client.py
```

Kết quả mong đợi:
```
Status: 200
Response: {'message': 'API called successfully', 'jwt_verified': True, 'hmac_verified': True, 'user': 'demo', 'email': 'demo@gmail.com'}
```

### 1️⃣1️⃣ Kiểm tra chống replay

Chạy client HMAC **lần đầu** → thành công.
Chạy client HMAC **lần thứ hai ngay lập tức** → lỗi 401 với message `"Nonce already used"`.

---

## 🧪 Kiểm thử bằng curl

### Lấy token từ Keycloak (dùng password flow - chỉ để test)

```bash
curl -X POST http://localhost:8080/realms/api-gateway-demo/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=api-spa" \
  -d "username=demo" \
  -d "password=demo123" \
  -d "grant_type=password"
```

### Gọi API qua Kong

```bash
TOKEN="<access_token từ response trên>"
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/public
```

---

## 📁 Cấu trúc thư mục

```
Secure-API-Gateway-with-Cryptographic-Enforcement/
├── infra/                      # Docker và cấu hình Kong
│   ├── docker-compose.yml
│   ├── docker-compose.kong.yml
│   └── kong.yml
├── services/                   # Backend FastAPI
│   └── backend.py
├── clients/                    # Client apps
│   ├── spa/
│   │   └── index.html          # Website OAuth2 PKCE
│   └── hmac_client.py          # Client HMAC signing
├── requirements.txt            # Python dependencies
└── README.md                   # Hướng dẫn này
```

---

## 📊 Luồng hoạt động chi tiết

### 1. OAuth2 PKCE (Website)
1. Website tạo `code_verifier` và `code_challenge`
2. Redirect đến Keycloak kèm `code_challenge`
3. Người dùng đăng nhập, Keycloak tạo `code`
4. Website đổi `code` + `verifier` lấy `access_token`

### 2. Gọi API (chỉ JWT)
1. Website gửi request với header `Authorization: Bearer {token}`
2. Kong forward request đến backend
3. Backend verify JWT (chữ ký, exp, aud, iss)
4. Backend trả về response

### 3. Gọi API có HMAC (machine-to-machine)
1. Client tạo `timestamp`, `nonce`, `canonical string`
2. Client tính HMAC signature
3. Gửi request kèm JWT + 3 header HMAC
4. Backend verify:
   - JWT (như trên)
   - Timestamp (còn hiệu lực 60s)
   - Nonce (chưa dùng)
   - HMAC signature
5. Trả về `hmac_verified: true`
