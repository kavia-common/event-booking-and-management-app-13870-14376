from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer

security = HTTPBearer(auto_error=False)

class UserInfo(BaseModel):
    id: str = Field(..., description="User ID")
    email: Optional[str] = Field(None, description="Email")
    roles: List[str] = Field(default_factory=list, description="Roles")

def require_roles(required: List[str]):
    async def _inner(user: Optional[UserInfo] = Depends(lambda: None)) -> UserInfo:
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        if required and not any(r in user.roles for r in required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user
    return _inner
