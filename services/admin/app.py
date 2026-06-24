from fastapi import FastAPI, HTTPException, Header
import uvicorn
import os
import sys
sys.path.append("..")
from shared.models import User

app = FastAPI(title="Admin Service")

# Mock users
users = {
    "user1": {"user_id": "user1", "username": "demo", "email": "demo@bank.com", "full_name": "Demo User", "role": "user"},
    "user2": {"user_id": "user2", "username": "alice", "email": "alice@bank.com", "full_name": "Alice Johnson", "role": "user"},
    "admin": {"user_id": "admin", "username": "admin", "email": "admin@bank.com", "full_name": "Admin", "role": "admin"}
}

# ✅ KHÔNG KIỂM TRA ROLE - GATEWAY ĐÃ LÀM
@app.get("/users")
async def list_users(authorization: str = Header(None)):
    return {"users": list(users.values())}

@app.get("/users/{user_id}")
async def get_user(user_id: str, authorization: str = Header(None)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

@app.post("/users")
async def create_user(user: User, authorization: str = Header(None)):
    if user.user_id in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[user.user_id] = user.dict()
    return {"message": "User created", "user": user}

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, authorization: str = Header(None)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[user_id]
    return {"message": f"User {user_id} deleted"}

@app.put("/users/{user_id}/role")
async def update_user_role(user_id: str, role: str, authorization: str = Header(None)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[user_id]["role"] = role
    return {"message": f"User {user_id} role updated to {role}", "user": users[user_id]}

@app.get("/system/stats")
async def system_stats(authorization: str = Header(None)):
    return {
        "total_users": len(users),
        "total_accounts": 4,
        "total_balance": 120000000,
        "system_status": "operational",
        "uptime": "99.95%"
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "admin"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5003)
