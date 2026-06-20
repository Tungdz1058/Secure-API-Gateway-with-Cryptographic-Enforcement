# Secure API Gateway with Cryptographic Enforcement

## 📌 Mô tả đồ án

Đồ án triển khai **API Gateway an toàn** với các cơ chế mật mã:
- **OAuth2 / OpenID Connect** (PKCE) - Xác thực người dùng qua Auth0
- **JWT** (RS256) - Token-based authentication/authorization
- **HMAC request signing** - Đảm bảo tính toàn vẹn và chống replay
- **Redis / In-memory** - Lưu nonce để chống tấn công replay
- **Token Revocation** - Thu hồi token khi logout
- **Session Management** - Active session check
- **Key Rotation (KMS)** - Xoay vòng HMAC secret

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────────────────┐
│                               HỆ THỐNG                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐     ┌─────────────────────┐     ┌─────────────────┐   │
│  │   Website   │────▶│   Backend FastAPI   │────▶│     Redis       │   │
│  │   (Vercel)  │     │   (API Gateway +    │     │  (Nonce Store)  │   │
│  │             │     │    Crypto Enforce)  │     │                 │   │
│  └─────────────┘     └─────────────────────┘     └─────────────────┘   │
│         │                     │                         │              │
│         ▼                     ▼                         ▼              │
│  ┌─────────────┐     ┌─────────────────────┐     ┌─────────────────┐   │
│  │   Auth0     │     │   JWT + HMAC +      │     │   Session       │   │
│  │   (IdP)     │     │   Session + Revoke  │     │   Store         │   │
│  └─────────────┘     └─────────────────────┘     └─────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Công nghệ sử dụng

| Thành phần | Công nghệ | Vai trò |
|------------|-----------|---------|
| **Identity Provider** | Auth0 | Cấp JWT token, quản lý danh tính |
| **API Gateway + Backend** | FastAPI (Python) | Xác thực JWT, HMAC, nonce, session, revocation |
| **Nonce Store** | Redis / In-memory | Lưu nonce đã dùng, chống replay |
| **Website** | HTML/JS (SPA) | OAuth2 PKCE, gọi API |
| **Deployment** | Vercel (FE), Render (BE) | Cloud deployment |

---

## 🔐 Các cơ chế bảo mật đã triển khai

| STT | Cơ chế | Vị trí triển khai |
|-----|--------|-------------------|
| 1 | **OAuth2 + PKCE** | Website (Auth0) |
| 2 | **JWT RS256 Verification** | Backend FastAPI |
| 3 | **HMAC Request Signing** | Backend FastAPI |
| 4 | **Nonce (chống replay)** | Backend FastAPI + Redis |
| 5 | **Timestamp (60s)** | Backend FastAPI |
| 6 | **Token Revocation** | Backend FastAPI |
| 7 | **Session Management** | Backend FastAPI |
| 8 | **Key Rotation (KMS)** | Backend FastAPI |
| 9 | **Admin Role Check** | Backend FastAPI |
| 10 | **CORS** | Backend FastAPI |

---

## 📋 Yêu cầu hệ thống

- **Ubuntu 22.04 / 24.04** (hoặc WSL2 trên Windows)
- **Docker** (cho Redis)
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

### 3️⃣ Khởi động Redis (lưu nonce)

```bash
docker run -d --name redis -p 6379:6379 redis
# Hoặc nếu đã có container cũ:
docker start redis
```

### 4️⃣ Khởi động Backend FastAPI (API Gateway)

```bash
cd ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement
source venv/bin/activate
python services/backend.py
```

Giữ terminal này chạy.

### 5️⃣ Khởi động Website

```bash
cd ~/Final_Project/Secure-API-Gateway-with-Cryptographic-Enforcement/clients/spa
python3 -m http.server 3000
```

### 6️⃣ Cấu hình Auth0

**Auth0 Dashboard → Applications → Create Application (SPA)**

- **Allowed Callback URLs:** `http://localhost:3000`, `https://secure-api-gateway-with-cryptograph.vercel.app`
- **Allowed Logout URLs:** `http://localhost:3000`, `https://secure-api-gateway-with-cryptograph.vercel.app`
- **Allowed Web Origins:** `http://localhost:3000`, `https://secure-api-gateway-with-cryptograph.vercel.app`

**Auth0 Dashboard → APIs → Create API**

- **Identifier:** `https://api-gateway-demo.com`
- **Signing Algorithm:** RS256
- **Enable RBAC:** ON
- **Add Permissions in the Access Token:** ON

---

## 🧪 Test luồng bảo mật trên Console (F12)

### 1. Lấy token và Login (Active Session)

```javascript
var token = "YOUR_JWT_TOKEN_FROM_AUTH0";

// Active session
fetch('https://secure-api-gateway-backend.onrender.com/api/login', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token }
})
.then(res => res.json())
.then(data => console.log('Login:', data));
// {"message":"Login successful","user":"auth0|..."}
```

### 2. Gọi API (JWT Only)

```javascript
fetch('https://secure-api-gateway-backend.onrender.com/api/public', {
    headers: { 'Authorization': 'Bearer ' + token }
})
.then(res => res.json())
.then(data => console.log('API:', data));
// {"message":"API called successfully","jwt_verified":true,"hmac_verified":false,...}
```

### 3. Gọi API có HMAC

```javascript
var timestamp = Math.floor(Date.now() / 1000).toString();
var nonce = crypto.randomUUID();
var signature = "YOUR_HMAC_SIGNATURE"; // Tính HMAC

fetch('https://secure-api-gateway-backend.onrender.com/api/public', {
    headers: {
        'Authorization': 'Bearer ' + token,
        'X-Timestamp': timestamp,
        'X-Nonce': nonce,
        'X-Signature': signature
    }
})
.then(res => res.json())
.then(data => console.log('API + HMAC:', data));
// {"message":"API called successfully","jwt_verified":true,"hmac_verified":true,...}
```

### 4. Logout (Token Revocation)

```javascript
fetch('https://secure-api-gateway-backend.onrender.com/api/revoke', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + token }
})
.then(res => res.json())
.then(data => console.log('Logout:', data));
// {"message":"Logged out successfully","user":"auth0|..."}

// Token cũ bị từ chối
fetch('https://secure-api-gateway-backend.onrender.com/api/public', {
    headers: { 'Authorization': 'Bearer ' + token }
})
.then(res => res.json())
.then(data => console.log('Sau logout:', data));
// {"detail":"Token revoked"}
```

### 5. Key Rotation (Admin Only)

```javascript
var adminToken = "YOUR_ADMIN_TOKEN";

// Xem danh sách key
fetch('https://secure-api-gateway-backend.onrender.com/api/keys')
.then(res => res.json())
.then(data => console.log('Keys:', data));

// Rotate key (cần admin)
fetch('https://secure-api-gateway-backend.onrender.com/api/rotate', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + adminToken }
})
.then(res => res.json())
.then(data => console.log('Rotate:', data));
// {"message":"Key rotated","new_key_id":"hmac-v1:..."}
```

---

## 📁 Cấu trúc thư mục

```
Secure-API-Gateway-with-Cryptographic-Enforcement/
├── services/
│   └── backend.py              # FastAPI (API Gateway + Crypto)
├── clients/
│   ├── spa/
│   │   └── index.html          # Website OAuth2 PKCE
│   └── hmac_client.py          # Client HMAC signing
├── tests/                      # Unit tests
│   ├── test_backend.py
│   └── test_security.py
├── requirements.txt
└── README.md
```

---

## 📊 Tóm tắt các API endpoints

| API | Method | Mô tả | Yêu cầu |
|-----|--------|-------|---------|
| `/api/login` | POST | Active session | JWT |
| `/api/public` | GET | Gọi API (JWT + HMAC) | JWT |
| `/api/revoke` | POST | Logout / Revoke token | JWT |
| `/api/keys` | GET | Xem danh sách HMAC key | - |
| `/api/rotate` | POST | Xoay HMAC key (admin) | JWT (admin role) |
| `/admin/health` | GET | Health check | - |

---

## 🧑‍💻 Thành viên nhóm

| STT | Họ và tên | MSSV |
|-----|-----------|------|
| 1 | Lê Đình Tùng | 24162140 |
| 2 | Trần Ngô Anh Tú | 24152141 |
| 3 | Cao Nhứt Thạnh | 24162118 |
