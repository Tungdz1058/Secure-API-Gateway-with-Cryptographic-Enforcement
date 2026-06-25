from fastapi import FastAPI, HTTPException, Depends
import uvicorn
import sys
sys.path.append("..")
from shared.models import User
from shared.gateway_auth import verify_gateway_request

app = FastAPI(title="Admin Service")

users = {
    "user1": {"user_id": "user1", "username": "demo", "email": "demo@bank.com", "full_name": "Demo User", "role": "user"},
    "user2": {"user_id": "user2", "username": "alice", "email": "alice@bank.com", "full_name": "Alice Johnson", "role": "user"},
    "admin": {"user_id": "admin", "username": "admin", "email": "admin@bank.com", "full_name": "Admin", "role": "admin"},
}


def require_admin(gateway_user: dict):
    if "admin" not in gateway_user.get("roles", []):
        raise HTTPException(status_code=403, detail="Admin role required")

@app.get("/users")
async def list_users(gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    return {"users": list(users.values()), "requested_by": gateway_user["user_id"]}

@app.get("/users/{user_id}")
async def get_user(user_id: str, gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]

@app.post("/users")
async def create_user(user: User, gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    if user.user_id in users:
        raise HTTPException(status_code=400, detail="User already exists")
    users[user.user_id] = user.dict()
    return {"message": "User created", "user": user, "requested_by": gateway_user["user_id"]}

@app.delete("/users/{user_id}")
async def delete_user(user_id: str, gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[user_id]
    return {"message": f"User {user_id} deleted", "requested_by": gateway_user["user_id"]}

@app.put("/users/{user_id}/role")
async def update_user_role(user_id: str, role: str, gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    users[user_id]["role"] = role
    return {"message": f"User {user_id} role updated to {role}", "user": users[user_id]}

@app.get("/system/stats")
async def system_stats(gateway_user=Depends(verify_gateway_request)):
    require_admin(gateway_user)
    return {
        "total_users": len(users),
        "total_accounts": 4,
        "total_balance": 120000000,
        "system_status": "operational",
        "uptime": "99.95%",
        "requested_by": gateway_user["user_id"],
    }

@app.get("/health")
async def health():
    return {"status": "ok", "service": "admin"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5003)
