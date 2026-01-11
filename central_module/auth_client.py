import redis
import httpx
from typing import Optional
import os
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()
redis_client = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8080")

async def verify_token(token: str) -> Optional[dict]:
    """Проверка токена через auth-сервис"""
    # Сначала проверяем кэш
    try:
        cached_user = redis_client.get(f"token:{token}")
        if cached_user:
            import json
            return json.loads(cached_user.decode())
    except Exception:
        pass
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{AUTH_SERVICE_URL}/api/v1/verify",
                json={"token": token},
                timeout=10.0
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("valid"):
                    user_data = data.get("user", {})
                    # Кэшируем на 5 минут
                    import json
                    redis_client.setex(f"token:{token}", 300, json.dumps(user_data))
                    return user_data
    except Exception as e:
        print(f"Auth service error: {e}")
    
    return None

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Dependency для получения текущего пользователя"""
    token = credentials.credentials
    user = await verify_token(token)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Добавляем токен в user для использования в других запросах
    user["token"] = token
    return user

def require_role(required_role: str):
    """Декоратор для проверки роли"""
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user.get("role") != required_role:
            raise HTTPException(
                status_code=403,
                detail=f"Requires {required_role} role"
            )
        return current_user
    return role_checker
