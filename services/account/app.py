from fastapi import FastAPI, HTTPException, Depends
import uvicorn
import sys

sys.path.append("..")

from shared.gateway_auth import verify_gateway_request


app = FastAPI(title="Account Service")


# Mock account database.
# Trong production, owner_id sẽ lấy từ database.
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


def is_admin(gateway_user: dict) -> bool:
    """
    Kiểm tra user hiện tại có role admin hay không.
    gateway_user được lấy từ verify_gateway_request.
    """
    roles = gateway_user.get("roles", [])
    return "admin" in roles


def public_account_view(account: dict) -> dict:
    """
    Dữ liệu trả về cho user thường.
    Không trả owner_id để tránh lộ thông tin nội bộ.
    """
    return {
        "account_id": account["account_id"],
        "balance": account["balance"],
        "currency": account["currency"],
        "status": account["status"],
    }


def assert_can_access_account(account_id: str, gateway_user: dict) -> dict:
    """
    BOLA / IDOR protection.

    Token hợp lệ chưa đủ.
    User chỉ được truy cập account có owner_id trùng với X-User-Id.
    Admin được phép truy cập tất cả account.
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
            detail="BOLA blocked: you are not allowed to access this account"
        )

    return account


@app.get("/")
async def root():
    return {
        "message": "Account Service is running",
        "service": "account"
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "account"
    }


@app.get("/me/accounts")
async def get_my_accounts(gateway_user=Depends(verify_gateway_request)):
    """
    Endpoint an toàn hơn /user/{user_id}.
    User không tự truyền user_id nữa.
    Service tự lấy user_id từ Gateway sau khi JWT/session/role đã được verify.
    """
    current_user_id = gateway_user.get("user_id")

    if not current_user_id:
        raise HTTPException(
            status_code=401,
            detail="Missing authenticated user identity"
        )

    if is_admin(gateway_user):
        return {
            "user_id": current_user_id,
            "role": "admin",
            "accounts": list(accounts.values()),
            "total_balance": sum(acc["balance"] for acc in accounts.values()),
        }

    user_accounts = [
        public_account_view(account)
        for account in accounts.values()
        if account.get("owner_id") == current_user_id
    ]

    if not user_accounts:
        raise HTTPException(
            status_code=404,
            detail="Authenticated user has no accounts"
        )

    return {
        "user_id": current_user_id,
        "accounts": user_accounts,
        "total_balance": sum(acc["balance"] for acc in user_accounts),
    }


@app.get("/{account_id}")
async def get_account(
    account_id: str,
    gateway_user=Depends(verify_gateway_request)
):
    """
    Lấy thông tin một account.
    Có chống BOLA:
    - User thường chỉ xem account của chính mình.
    - Admin xem được tất cả.
    """
    account = assert_can_access_account(account_id, gateway_user)

    if is_admin(gateway_user):
        return {
            **account,
            "requested_by": gateway_user.get("user_id"),
        }

    return {
        **public_account_view(account),
        "requested_by": gateway_user.get("user_id"),
    }


@app.get("/user/{user_id}")
async def get_user_accounts(
    user_id: str,
    gateway_user=Depends(verify_gateway_request)
):
    """
    Endpoint cũ.
    Vẫn giữ để không làm hỏng frontend/code cũ,
    nhưng thêm kiểm soát BOLA.

    User thường chỉ được xem tài khoản của chính mình.
    Admin được xem tài khoản của bất kỳ user nào.
    """
    current_user_id = gateway_user.get("user_id")

    if not current_user_id:
        raise HTTPException(
            status_code=401,
            detail="Missing authenticated user identity"
        )

    if not is_admin(gateway_user) and user_id != current_user_id:
        raise HTTPException(
            status_code=403,
            detail="BOLA blocked: cannot access another user's accounts"
        )

    if is_admin(gateway_user):
        user_accounts = [
            account
            for account in accounts.values()
            if account.get("owner_id") == user_id
        ]
    else:
        user_accounts = [
            public_account_view(account)
            for account in accounts.values()
            if account.get("owner_id") == current_user_id
        ]

    if not user_accounts:
        raise HTTPException(
            status_code=404,
            detail="User has no accounts"
        )

    return {
        "user_id": user_id,
        "accounts": user_accounts,
        "total_balance": sum(acc["balance"] for acc in user_accounts),
        "requested_by": current_user_id,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)
