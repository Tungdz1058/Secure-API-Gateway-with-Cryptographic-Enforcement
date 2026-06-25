from fastapi import FastAPI, HTTPException, Depends
import uvicorn
import sys
sys.path.append("..")
from shared.gateway_auth import verify_gateway_request

app = FastAPI(title="Account Service")

accounts = {
    "ACC001": {"user_id": "user1", "balance": 15000000, "currency": "VND", "status": "active"},
    "ACC002": {"user_id": "user2", "balance": 5000000, "currency": "VND", "status": "active"},
    "ACC003": {"user_id": "admin", "balance": 100000000, "currency": "VND", "status": "active"},
    "ACC004": {"user_id": "user1", "balance": 500, "currency": "USD", "status": "active"},
}

@app.get("/")
async def root():
    return {"message": "Account Service is running", "service": "account"}

@app.get("/health")
async def health():
    return {"status": "ok", "service": "account"}

@app.get("/{account_id}")
async def get_account(account_id: str, gateway_user=Depends(verify_gateway_request)):
    if account_id not in accounts:
        raise HTTPException(status_code=404, detail="Account not found")

    account = accounts[account_id]
    return {
        "account_id": account_id,
        "user_id": account["user_id"],
        "balance": account["balance"],
        "currency": account["currency"],
        "status": account["status"],
        "requested_by": gateway_user["user_id"],
    }

@app.get("/user/{user_id}")
async def get_user_accounts(user_id: str, gateway_user=Depends(verify_gateway_request)):
    # User thường chỉ được xem tài khoản của chính mình; admin được xem tất cả.
    # Demo đang map user_id nội bộ đơn giản nên vẫn giữ dữ liệu mock như cũ.
    user_accounts = []
    for acc_id, acc in accounts.items():
        if acc["user_id"] == user_id:
            user_accounts.append({
                "account_id": acc_id,
                "balance": acc["balance"],
                "currency": acc["currency"],
                "status": acc["status"],
            })

    if not user_accounts:
        raise HTTPException(status_code=404, detail="User has no accounts")

    return {
        "user_id": user_id,
        "accounts": user_accounts,
        "total_balance": sum(a["balance"] for a in user_accounts),
        "requested_by": gateway_user["user_id"],
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)
