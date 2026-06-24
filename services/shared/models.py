from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    user_id: str
    username: str
    email: str
    full_name: str
    role: str = "user"

class Account(BaseModel):
    account_id: str
    user_id: str
    balance: float
    currency: str = "VND"
    status: str = "active"

class TransferRequest(BaseModel):
    from_account: str
    to_account: str
    amount: float
    description: Optional[str] = None

class TransferResponse(BaseModel):
    transaction_id: str
    from_account: str
    to_account: str
    amount: float
    fee: float
    status: str
    timestamp: str

class WithdrawRequest(BaseModel):
    account_id: str
    amount: float
    description: Optional[str] = None
