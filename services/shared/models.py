from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


class StrictBaseModel(BaseModel):
    """
    Base model dùng cho request từ client.
    extra = "forbid" giúp chặn field lạ để chống Mass Assignment.
    """

    class Config:
        extra = "forbid"


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


class TransferRequest(StrictBaseModel):
    from_account: str = Field(..., min_length=1, max_length=50)
    to_account: str = Field(..., min_length=1, max_length=50)
    amount: float = Field(..., gt=0)
    description: Optional[str] = Field(default=None, max_length=255)


class TransferResponse(BaseModel):
    transaction_id: str
    from_account: str
    to_account: str
    amount: float
    fee: float
    status: str
    timestamp: str


class WithdrawRequest(StrictBaseModel):
    account_id: str = Field(..., min_length=1, max_length=50)
    amount: float = Field(..., gt=0)
    description: Optional[str] = Field(default=None, max_length=255)
