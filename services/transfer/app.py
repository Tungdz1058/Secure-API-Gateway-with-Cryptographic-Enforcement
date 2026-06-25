from fastapi import FastAPI, HTTPException, Depends
import uvicorn
import uuid
from datetime import datetime
import sys

sys.path.append("..")

from shared.models import TransferRequest, TransferResponse, WithdrawRequest
from shared.gateway_auth import verify_gateway_request


app = FastAPI(title="Transfer Service")


# Mock account database.
# Trong production, dữ liệu này nên lấy từ Account Service hoặc database thật.
# owner_id phải khớp với Auth0 "sub" của user.
accounts = {
    "ACC001": {
        "account_id": "ACC001",
        "owner_id": "auth0|6a2cd06b23a8f6df6a9e26e3",
        "balance": 15000000,
        "currency": "VND",
        "status": "active",
    },
    "ACC002": {
        "account_id": "ACC002",
        "owner_id": "auth0|another-user-demo",
        "balance": 5000000,
        "currency": "VND",
        "status": "active",
    },
    "ACC003": {
        "account_id": "ACC003",
        "owner_id": "auth0|admin-demo",
        "balance": 100000000,
        "currency": "VND",
        "status": "active",
    },
    "ACC004": {
        "account_id": "ACC004",
        "owner_id": "auth0|6a2cd06b23a8f6df6a9e26e3",
        "balance": 500,
        "currency": "USD",
        "status": "active",
    },
}


transactions = []


def is_admin(gateway_user: dict) -> bool:
    roles = gateway_user.get("roles", [])
    return "admin" in roles


def assert_can_access_account(account_id: str, gateway_user: dict) -> dict:
    """
    BOLA / IDOR protection.

    User thường chỉ được thao tác với account có owner_id trùng X-User-Id.
    Admin được phép thao tác tất cả account.
    """
    account = accounts.get(account_id)

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    current_user_id = gateway_user.get("user_id")

    if not current_user_id:
        raise HTTPException(
            status_code=401,
            detail="Missing authenticated user identity"
        )

    if is_admin(gateway_user):
        return account

    if account.get("owner_id") != current_user_id:
        raise HTTPException(
            status_code=403,
            detail="blocked: you are not allowed to use this account"
        )

    return account


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "transfer"
    }


@app.post("/transfer")
async def transfer_money(
    request: TransferRequest,
    gateway_user=Depends(verify_gateway_request),
):
    """
    Chuyển tiền có chống BOLA và Mass Assignment.

    Mass Assignment được chặn trong TransferRequest:
    - Không cho client gửi field lạ như fee, status, balance, role, is_admin.
    - amount phải > 0.
    """
    if request.from_account not in accounts:
        raise HTTPException(status_code=404, detail="Source account not found")

    if request.to_account not in accounts:
        raise HTTPException(status_code=404, detail="Destination account not found")

    from_acc = assert_can_access_account(request.from_account, gateway_user)
    to_acc = accounts[request.to_account]

    if from_acc["status"] != "active":
        raise HTTPException(status_code=400, detail="Source account is not active")

    if to_acc["status"] != "active":
        raise HTTPException(status_code=400, detail="Destination account is not active")

    # Pydantic đã kiểm tra amount > 0, nhưng giữ thêm check này để defense-in-depth.
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    fee = request.amount * 0.001
    total_debit = request.amount + fee

    if from_acc["balance"] < total_debit:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    from_acc["balance"] -= total_debit
    to_acc["balance"] += request.amount

    transaction = {
        "transaction_id": str(uuid.uuid4()),
        "from_account": request.from_account,
        "to_account": request.to_account,
        "amount": request.amount,
        "fee": fee,
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "description": request.description,
        "requested_by": gateway_user["user_id"],
    }

    transactions.append(transaction)

    return TransferResponse(
        transaction_id=transaction["transaction_id"],
        from_account=request.from_account,
        to_account=request.to_account,
        amount=request.amount,
        fee=fee,
        status="completed",
        timestamp=transaction["timestamp"],
    )


@app.post("/withdraw")
async def withdraw_money(
    request: WithdrawRequest,
    gateway_user=Depends(verify_gateway_request),
):
    """
    Rút tiền có chống BOLA và Mass Assignment.

    Mass Assignment được chặn trong WithdrawRequest:
    - Không cho client gửi field lạ như balance, role, is_admin, status.
    - amount phải > 0.
    """
    account = assert_can_access_account(request.account_id, gateway_user)

    if account["status"] != "active":
        raise HTTPException(status_code=400, detail="Account is not active")

    # Pydantic đã kiểm tra amount > 0, nhưng giữ thêm check này để defense-in-depth.
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    if account["balance"] < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    account["balance"] -= request.amount

    transaction = {
        "transaction_id": str(uuid.uuid4()),
        "account_id": request.account_id,
        "type": "withdraw",
        "amount": request.amount,
        "status": "completed",
        "timestamp": datetime.now().isoformat(),
        "description": request.description,
        "requested_by": gateway_user["user_id"],
    }

    transactions.append(transaction)

    return {
        "message": "Withdrawal successful",
        "transaction_id": transaction["transaction_id"],
        "amount": request.amount,
        "new_balance": account["balance"],
        "timestamp": transaction["timestamp"],
    }


@app.get("/history")
async def get_history(
    account_id: str,
    gateway_user=Depends(verify_gateway_request),
):
    """
    Xem lịch sử giao dịch có chống BOLA.
    """
    assert_can_access_account(account_id, gateway_user)

    user_transactions = [
        t for t in transactions
        if t.get("from_account") == account_id
        or t.get("to_account") == account_id
        or t.get("account_id") == account_id
    ]

    return {
        "account_id": account_id,
        "transactions": user_transactions[-10:],
        "total": len(user_transactions),
        "requested_by": gateway_user["user_id"],
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)
