from fastapi import FastAPI, HTTPException, Depends
import uvicorn
import uuid
from datetime import datetime
import sys
sys.path.append("..")
from shared.models import TransferRequest, TransferResponse, WithdrawRequest
from shared.gateway_auth import verify_gateway_request

app = FastAPI(title="Transfer Service")

accounts = {
    "ACC001": {"user_id": "user1", "balance": 15000000, "currency": "VND"},
    "ACC002": {"user_id": "user2", "balance": 5000000, "currency": "VND"},
    "ACC003": {"user_id": "admin", "balance": 100000000, "currency": "VND"},
}

transactions = []

@app.get("/health")
async def health():
    return {"status": "ok", "service": "transfer"}

@app.post("/transfer")
async def transfer_money(
    request: TransferRequest,
    gateway_user=Depends(verify_gateway_request),
):
    if request.from_account not in accounts:
        raise HTTPException(status_code=404, detail="Source account not found")
    if request.to_account not in accounts:
        raise HTTPException(status_code=404, detail="Destination account not found")

    from_acc = accounts[request.from_account]
    to_acc = accounts[request.to_account]

    if from_acc["balance"] < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    fee = request.amount * 0.001
    from_acc["balance"] -= (request.amount + fee)
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
    if request.account_id not in accounts:
        raise HTTPException(status_code=404, detail="Account not found")

    account = accounts[request.account_id]
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
async def get_history(account_id: str, gateway_user=Depends(verify_gateway_request)):
    user_transactions = [
        t for t in transactions
        if t.get("from_account") == account_id or t.get("account_id") == account_id
    ]
    return {
        "account_id": account_id,
        "transactions": user_transactions[-10:],
        "total": len(user_transactions),
        "requested_by": gateway_user["user_id"],
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)
