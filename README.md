# Secure API Gateway - Cryptographic Enforcement

## 📌 Giới thiệu

Hệ thống API Gateway bảo mật với các cơ chế mật mã:
- **OAuth2 + PKCE** (Auth0) - Xác thực người dùng
- **JWT RS256** - Token-based authentication
- **HMAC-SHA256** - Request signing
- **Nonce + Timestamp** - Chống replay attack
- **Token Revocation** - Thu hồi token khi logout
- **Role-based Access Control** - Phân quyền (user/admin)

---

## 🏗️ Kiến trúc

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Frontend   │────▶│     Gateway      │────▶│   Auth Service   │
│   (Vercel)   │     │   (Render)       │     │   (Render)       │
└──────────────┘     └────────┬─────────┘     └──────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  Transfer        │ │  Account         │ │  Admin           │
│  Service         │ │  Service         │ │  Service         │
│  (Render)        │ │  (Render)        │ │  (Render)        │
└──────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 🛠️ Công nghệ

| Thành phần | Công nghệ |
|------------|-----------|
| **Frontend** | HTML + JavaScript (SPA) |
| **Gateway** | FastAPI (Python) |
| **Auth Service** | FastAPI (Python) |
| **Microservices** | FastAPI (Python) |
| **IdP** | Auth0 |
| **Deployment** | Vercel (FE), Render (BE) |

---

## 🔐 Role Permissions

| Service | User | Admin |
|---------|------|-------|
| **Transfer** | ✅ | ✅ |
| **Account** | ✅ | ✅ |
| **Admin** | ❌ | ✅ |

---

## 🚀 Quick Start

### 1️⃣ Clone repository
```bash
git clone git@github.com:Tungdz1058/Secure-API-Gateway-with-Cryptographic-Enforcement.git
cd Secure-API-Gateway-with-Cryptographic-Enforcement
```

### 2️⃣ Setup Python environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3️⃣ Run locally
```bash
# Gateway
cd gateway && uvicorn gateway:app --port 8000

# Auth Service
cd services/auth && uvicorn app:app --port 5000

# Transfer Service
cd services/transfer && uvicorn app:app --port 5001

# Account Service
cd services/account && uvicorn app:app --port 5002

# Admin Service
cd services/admin && uvicorn app:app --port 5003
```

### 4️⃣ Frontend
```bash
cd clients/spa
python3 -m http.server 3000
```

Truy cập: `http://localhost:3000`

---

## 🌐 Cloud URLs

| Service | URL |
|---------|-----|
| **Frontend** | `https://secure-api-gateway-with-cryptograph.vercel.app` |
| **Gateway** | `https://bank-gateway-khpy.onrender.com` |
| **Auth** | `https://bank-auth.onrender.com` |
| **Transfer** | `https://bank-transfer-vd1p.onrender.com` |
| **Account** | `https://bank-account-corr.onrender.com` |
| **Admin** | `https://bank-admin-ou0n.onrender.com` |

---

## 🧪 Test

```bash
# JWT + HMAC
curl -X GET https://bank-gateway-khpy.onrender.com/api/account/ACC001 \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIGNATURE"

# Chuyển tiền
curl -X POST https://bank-gateway-khpy.onrender.com/api/transfer/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Nonce: $NONCE" \
  -H "X-Signature: $SIGNATURE" \
  -d '{"from_account":"ACC001","to_account":"ACC002","amount":100000}'
```

---

## 📂 Cấu trúc

```
├── gateway/
│   └── gateway.py
├── services/
│   ├── auth/
│   │   └── app.py
│   ├── transfer/
│   │   └── app.py
│   ├── account/
│   │   └── app.py
│   └── admin/
│       └── app.py
├── clients/
│   └── spa/
│       └── index.html
└── render.yaml
```

---

## 👥 Thành viên

| STT | Họ tên | MSSV |
|-----|--------|------|
| 1 | Lê Đình Tùng | 24162140 |
| 2 | Trần Ngô Anh Tú | 24152141 |
| 3 | Cao Nhứt Thạnh | 24162118 |

---

**🎉 Chúc các bạn hoàn thành đồ án tốt!**
