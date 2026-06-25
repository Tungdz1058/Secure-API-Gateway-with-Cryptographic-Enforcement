from fastapi import HTTPException


# Demo ownership mapping.
# Trong production, phần này nên lấy từ database.
ACCOUNT_OWNERS = {
    "ACC001": "auth0|6a2cd06b23a8f6df6a9e26e3",  # demo@gmail.com
    "ACC004": "auth0|6a2cd06b23a8f6df6a9e26e3",

    # Giả lập tài khoản của user khác để test BOLA
    "ACC002": "auth0|another-user-demo",
    "ACC003": "auth0|admin-demo",
}


def is_admin_user(gateway_user: dict) -> bool:
    roles = gateway_user.get("roles", [])
    return "admin" in roles


def assert_account_owner(account_id: str, gateway_user: dict):
    """
    Chặn BOLA/IDOR:
    - Admin được phép truy cập tất cả account.
    - User thường chỉ được truy cập account thuộc về chính user đó.
    """
    user_id = gateway_user.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Missing authenticated user identity"
        )

    if is_admin_user(gateway_user):
        return

    owner_id = ACCOUNT_OWNERS.get(account_id)

    if owner_id is None:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found"
        )

    if owner_id != user_id:
        raise HTTPException(
            status_code=403,
            detail=f"BOLA blocked: account {account_id} does not belong to the authenticated user"
        )
