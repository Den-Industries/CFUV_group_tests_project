from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import os
from sqlalchemy.exc import IntegrityError

import models
from database import get_db, engine
from auth_client import get_current_user, require_role

# Создаём таблицы
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Survey Central Module", version="1.0.0")

# Pydantic схемы
class TestCreate(BaseModel):
    title: str
    description: Optional[str] = None
    is_active: bool = True

class TestResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    created_by: int
    is_active: bool
    created_at: datetime

class QuestionCreate(BaseModel):
    question_text: str
    question_type: str = "single_choice"
    points: int = 1
    answers: List[dict]

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str]
    role: str

# Вспомогательная функция для получения или создания пользователя
def get_or_create_user(db: Session, auth_user: dict):
    """Получаем или создаем пользователя в нашей базе (синхронизация с MongoDB)"""
    # Проверяем, что auth_user не пустой
    if not auth_user or not isinstance(auth_user, dict):
        raise ValueError("Invalid auth_user data")
    
    # MongoDB ID может быть в разных форматах
    mongo_id = str(auth_user.get("id", "")) or str(auth_user.get("_id", ""))
    if not mongo_id or mongo_id == "None":
        mongo_id = f"local-{auth_user.get('username', 'unknown')}"
    
    auth_id = f"mongo-{mongo_id}" if mongo_id and not mongo_id.startswith("local-") else mongo_id
    
    username = auth_user.get("username", "")
    if not username:
        raise ValueError("Username is required")
    
    # Пытаемся найти пользователя по auth_id
    db_user = db.query(models.User).filter(models.User.auth_id == auth_id).first()
    
    if db_user:
        # Обновляем данные если нужно
        updated = False
        if db_user.username != username:
            db_user.username = username
            updated = True
        if db_user.email != auth_user.get("email"):
            db_user.email = auth_user.get("email", db_user.email)
            updated = True
        if db_user.role != auth_user.get("role"):
            db_user.role = auth_user.get("role", db_user.role)
            updated = True
        if updated:
            db.commit()
            db.refresh(db_user)
        return db_user
    
    # Если не нашли по auth_id, ищем по username
    db_user = db.query(models.User).filter(models.User.username == username).first()
    
    if db_user:
        # Обновляем auth_id если нашли по username
        db_user.auth_id = auth_id
        db_user.email = auth_user.get("email", db_user.email)
        db_user.role = auth_user.get("role", db_user.role)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    # Если пользователя нет вообще, создаем нового
    try:
        db_user = models.User(
            auth_id=auth_id,
            username=username,
            email=auth_user.get("email"),
            role=auth_user.get("role", "user")
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError:
        # Если произошла ошибка уникальности (например, username уже существует)
        db.rollback()
        # Генерируем уникальное имя пользователя
        db_user = models.User(
            auth_id=auth_id,
            username=f"{username}_{mongo_id[-8:]}",
            email=auth_user.get("email"),
            role=auth_user.get("role", "user")
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user

# Маршруты
@app.get("/")
async def root():
    return {"message": "Survey Central Module API", "status": "working"}

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "central_module", "timestamp": datetime.now()}

@app.get("/tests", response_model=List[TestResponse])
async def get_tests(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Получение списка активных тестов"""
    tests = db.query(models.Test).filter(models.Test.is_active == True).offset(skip).limit(limit).all()
    return tests

@app.get("/tests/all", response_model=List[TestResponse])
async def get_all_tests(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Получение всех тестов (только для админа)"""
    tests = db.query(models.Test).offset(skip).limit(limit).all()
    return tests

@app.post("/tests", response_model=TestResponse)
async def create_test(
    test: TestCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Создание нового теста (только для админа)"""
    
    # Получаем или создаем пользователя в нашей базе
    db_user = get_or_create_user(db, current_user)
    
    # Создаем тест
    db_test = models.Test(
        title=test.title,
        description=test.description,
        created_by=db_user.id,
        is_active=test.is_active
    )
    db.add(db_test)
    db.commit()
    db.refresh(db_test)
    
    return db_test

@app.get("/tests/{test_id}", response_model=TestResponse)
async def get_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Получение теста по ID"""
    db_test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not db_test:
        raise HTTPException(status_code=404, detail="Test not found")
    return db_test

@app.put("/tests/{test_id}", response_model=TestResponse)
async def update_test(
    test_id: int,
    test: TestCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Обновление теста (только для админа)"""
    db_test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not db_test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    # Проверяем, что тест создан текущим пользователем
    db_user = get_or_create_user(db, current_user)
    if db_test.created_by != db_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own tests")
    
    db_test.title = test.title
    db_test.description = test.description
    db_test.is_active = test.is_active
    db_test.updated_at = datetime.now()
    
    db.commit()
    db.refresh(db_test)
    return db_test

@app.delete("/tests/{test_id}")
async def delete_test(
    test_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Удаление теста (только для админа)"""
    db_test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not db_test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    # Проверяем, что тест создан текущим пользователем
    db_user = get_or_create_user(db, current_user)
    if db_test.created_by != db_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own tests")
    
    db.delete(db_test)
    db.commit()
    
    return {"message": f"Test {test_id} deleted successfully"}

@app.get("/tests/{test_id}/questions")
async def get_test_questions(
    test_id: int,
    db: Session = Depends(get_db)
):
    """Получение вопросов теста"""
    test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    questions = db.query(models.Question).filter(models.Question.test_id == test_id).all()
    
    # Преобразуем вопросы в формат для ответа
    result = []
    for q in questions:
        # Получаем ответы для вопроса
        answers = db.query(models.Answer).filter(models.Answer.question_id == q.id).all()
        answers_data = [{
            "id": a.id,
            "answer_text": a.answer_text,
            "is_correct": a.is_correct,
            "order_index": a.order_index
        } for a in answers]
        
        question_data = {
            "id": q.id,
            "test_id": q.test_id,
            "question_text": q.question_text,
            "question_type": q.question_type,
            "points": q.points,
            "answers": answers_data
        }
        result.append(question_data)
    
    return result

@app.post("/tests/{test_id}/questions")
async def add_question_to_test(
    test_id: int,
    question: QuestionCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Добавление вопроса к тесту (только для админа)"""
    test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    # Проверяем, что тест создан текущим пользователем
    db_user = get_or_create_user(db, current_user)
    if test.created_by != db_user.id:
        raise HTTPException(status_code=403, detail="You can only add questions to your own tests")
    
    # Создаем вопрос
    db_question = models.Question(
        test_id=test_id,
        question_text=question.question_text,
        question_type=question.question_type,
        points=question.points
    )
    db.add(db_question)
    db.commit()
    db.refresh(db_question)
    
    # Добавляем ответы
    for i, answer_data in enumerate(question.answers):
        db_answer = models.Answer(
            question_id=db_question.id,
            answer_text=answer_data.get("answer_text", ""),
            is_correct=answer_data.get("is_correct", False),
            order_index=i
        )
        db.add(db_answer)
    
    db.commit()
    
    return {"message": "Question added successfully", "question_id": db_question.id}

@app.put("/tests/{test_id}/questions/{question_id}")
async def update_question(
    test_id: int,
    question_id: int,
    question: QuestionCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Обновление вопроса (только для админа)"""
    test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    db_user = get_or_create_user(db, current_user)
    if test.created_by != db_user.id:
        raise HTTPException(status_code=403, detail="You can only edit questions in your own tests")
    
    db_question = db.query(models.Question).filter(
        models.Question.id == question_id,
        models.Question.test_id == test_id
    ).first()
    
    if not db_question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    # Обновляем вопрос
    db_question.question_text = question.question_text
    db_question.question_type = question.question_type
    db_question.points = question.points
    
    # Получаем старые ответы
    old_answers = db.query(models.Answer).filter(models.Answer.question_id == question_id).all()
    old_answer_ids = [a.id for a in old_answers]
    
    # Удаляем user_answers, которые ссылаются на старые ответы (чтобы избежать нарушения внешнего ключа)
    if old_answer_ids:
        db.query(models.UserAnswer).filter(models.UserAnswer.answer_id.in_(old_answer_ids)).delete(synchronize_session=False)
    
    # Удаляем старые ответы
    db.query(models.Answer).filter(models.Answer.question_id == question_id).delete()
    
    # Добавляем новые ответы
    for i, answer_data in enumerate(question.answers):
        db_answer = models.Answer(
            question_id=question_id,
            answer_text=answer_data.get("answer_text", ""),
            is_correct=answer_data.get("is_correct", False),
            order_index=i
        )
        db.add(db_answer)
    
    db.commit()
    db.refresh(db_question)
    
    return {"message": "Question updated successfully", "question_id": db_question.id}

@app.delete("/tests/{test_id}/questions/{question_id}")
async def delete_question(
    test_id: int,
    question_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Удаление вопроса (только для админа)"""
    test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    db_user = get_or_create_user(db, current_user)
    if test.created_by != db_user.id:
        raise HTTPException(status_code=403, detail="You can only delete questions from your own tests")
    
    db_question = db.query(models.Question).filter(
        models.Question.id == question_id,
        models.Question.test_id == test_id
    ).first()
    
    if not db_question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    db.delete(db_question)
    db.commit()
    
    return {"message": "Question deleted successfully"}

@app.post("/tests/{test_id}/submit")
async def submit_test(
    test_id: int,
    submission: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Отправка ответов на тест"""
    # Проверяем существование теста
    test = db.query(models.Test).filter(models.Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    
    if not test.is_active:
        raise HTTPException(status_code=400, detail="Test is not active")
    
    # Получаем или создаем пользователя
    db_user = get_or_create_user(db, current_user)
    
    # Получаем вопросы теста
    questions = db.query(models.Question).filter(models.Question.test_id == test_id).all()
    
    if not questions:
        raise HTTPException(status_code=400, detail="Test has no questions")
    
    # Обрабатываем ответы
    answers_data = submission.get("answers", [])
    total_score = 0
    max_score = sum(q.points for q in questions)
    
    # Создаем результат
    result = models.Result(
        user_id=db_user.id,
        test_id=test_id,
        score=0,
        max_score=max_score,
        answers_data={}
    )
    db.add(result)
    db.commit()
    db.refresh(result)
    
    # Обрабатываем каждый ответ
    user_answers_dict = {}
    for answer_data in answers_data:
        question_id = answer_data.get("question_id")
        answer_index = answer_data.get("answer_index")
        
        if question_id is None or answer_index is None:
            continue
        
        question = next((q for q in questions if q.id == question_id), None)
        if not question:
            continue
        
        # Получаем варианты ответов для вопроса
        answers = db.query(models.Answer).filter(models.Answer.question_id == question_id).order_by(models.Answer.order_index).all()
        
        if answer_index < len(answers):
            selected_answer = answers[answer_index]
            is_correct = selected_answer.is_correct
            points_earned = question.points if is_correct else 0
            total_score += points_earned
            
            # Создаем запись ответа пользователя
            user_answer = models.UserAnswer(
                result_id=result.id,
                question_id=question_id,
                answer_id=selected_answer.id,
                answer_text=selected_answer.answer_text,
                is_correct=is_correct,
                points_earned=points_earned
            )
            db.add(user_answer)
            user_answers_dict[question_id] = {
                "answer_id": selected_answer.id,
                "is_correct": is_correct,
                "points": points_earned
            }
    
    # Обновляем результат
    result.score = total_score
    result.answers_data = user_answers_dict
    db.commit()
    db.refresh(result)
    
    return {
        "result_id": result.id,
        "score": total_score,
        "max_score": max_score,
        "percentage": round((total_score / max_score * 100) if max_score > 0 else 0, 2),
        "completed_at": result.completed_at.isoformat()
    }

@app.get("/users")
async def get_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Получение списка пользователей (только для админа) - получает из auth модуля"""
    import httpx
    
    # Получаем пользователей из auth модуля (MongoDB)
    async with httpx.AsyncClient() as client:
        token = current_user.get("token") or ""
        try:
            response = await client.get(
                f"{os.getenv('AUTH_SERVICE_URL', 'http://auth_module:8080')}/api/v1/users",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Failed to fetch users from auth service")
            
            auth_users = response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"Auth service unavailable: {str(e)}")
    
    # Синхронизируем с PostgreSQL и возвращаем
    synced_users = []
    for auth_user in auth_users:
        # Проверяем, что auth_user не пустой
        if not auth_user or not isinstance(auth_user, dict):
            continue
            
        # MongoDB ID может быть строкой ObjectID
        mongo_id = auth_user.get("id") or auth_user.get("_id")
        if not mongo_id:
            continue
            
        db_user = get_or_create_user(db, {
            "id": str(mongo_id),  # Конвертируем в строку
            "username": auth_user.get("username", ""),
            "email": auth_user.get("email", ""),
            "role": auth_user.get("role", "user")
        })
        synced_users.append(db_user)
    
    return synced_users

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Получение пользователя по ID (только для админа)"""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.get("/results")
async def get_results(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Получение всех результатов тестов (только для админа)"""
    results = db.query(models.Result).offset(skip).limit(limit).all()
    
    # Обогащаем результаты данными о пользователях и тестах
    enriched_results = []
    for i in range(len(results) - 1, -1, -1):
        result = results[i]
        user = db.query(models.User).filter(models.User.id == result.user_id).first()
        test = db.query(models.Test).filter(models.Test.id == result.test_id).first()
        
        percentage = round((result.score / result.max_score * 100) if result.max_score > 0 else 0, 2)
        
        enriched_results.append({
            "id": result.id,
            "user_id": result.user_id,
            "user_username": user.username if user else "Неизвестно",
            "test_id": result.test_id,
            "test_title": test.title if test else "Неизвестно",
            "score": result.score,
            "max_score": result.max_score,
            "percentage": percentage,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None
        })
    
    return enriched_results

from passlib.context import CryptContext
from datetime import datetime

# Добавляем в начало файла после импортов
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    """Проверка пароля"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Хэширование пароля"""
    return pwd_context.hash(password)

# Схема для создания пользователя
class UserCreate(BaseModel):
    username: str
    email: Optional[str] = None
    password: str
    role: str = "user"

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None

# Добавляем новые маршруты для управления пользователями
@app.post("/users", response_model=UserResponse)
async def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Создание нового пользователя (только для админа) - проксирует в auth модуль"""
    import httpx
    
    # Создаем пользователя в auth модуле (MongoDB)
    async with httpx.AsyncClient() as client:
        token = current_user.get("token") or ""
        # Получаем токен из заголовка запроса
        try:
            response = await client.post(
                f"{os.getenv('AUTH_SERVICE_URL', 'http://auth_module:8080')}/api/v1/users",
                json={
                    "username": user.username,
                    "email": user.email,
                    "password": user.password,
                    "role": user.role
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            
            if response.status_code not in [200, 201]:
                try:
                    error_data = response.json()
                    error_detail = error_data.get("error", error_data.get("detail", response.text))
                except:
                    error_detail = response.text or "Auth service error"
                raise HTTPException(status_code=response.status_code, detail=error_detail)
            
            auth_user = response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"Auth service unavailable: {str(e)}")
    
    # Синхронизируем с PostgreSQL для связей с тестами
    db_user = get_or_create_user(db, {
        "id": auth_user.get("id"),
        "username": auth_user.get("username"),
        "email": auth_user.get("email"),
        "role": auth_user.get("role")
    })
    
    return db_user

@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Обновление пользователя (только для админа) - проксирует в auth модуль"""
    import httpx
    
    # Находим пользователя в PostgreSQL для получения auth_id
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Обновляем пользователя в auth модуле (MongoDB)
    async with httpx.AsyncClient() as client:
        token = current_user.get("token") or ""
        update_data = {}
        if user_update.username is not None:
            update_data["username"] = user_update.username
        if user_update.email is not None:
            update_data["email"] = user_update.email
        if user_update.role is not None:
            update_data["role"] = user_update.role
        if user_update.password is not None:
            update_data["password"] = user_update.password
        
        try:
            # Извлекаем MongoDB ID из auth_id
            mongo_id = db_user.auth_id.replace("mongo-", "") if db_user.auth_id and db_user.auth_id.startswith("mongo-") else (db_user.auth_id if db_user.auth_id else "")
            
            if not mongo_id:
                raise HTTPException(status_code=400, detail="User auth_id not found")
            
            response = await client.put(
                f"{os.getenv('AUTH_SERVICE_URL', 'http://auth_module:8080')}/api/v1/users/{mongo_id}",
                json=update_data,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                try:
                    error_data = response.json()
                    error_detail = error_data.get("error", error_data.get("detail", response.text))
                except:
                    error_detail = response.text or "Auth service error"
                raise HTTPException(status_code=response.status_code, detail=error_detail)
            
            auth_user = response.json()
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"Auth service unavailable: {str(e)}")
    
    # Синхронизируем с PostgreSQL
    db_user.username = auth_user.get("username", db_user.username)
    db_user.email = auth_user.get("email", db_user.email)
    db_user.role = auth_user.get("role", db_user.role)
    db_user.auth_id = f"mongo-{auth_user.get('id')}"
    db.commit()
    db.refresh(db_user)
    
    return db_user

@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Удаление пользователя (только для админа) - проксирует в auth модуль"""
    import httpx
    
    # Находим пользователя в PostgreSQL
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Не позволяем удалять самого себя
    if db_user.username == current_user.get("username"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    # Удаляем из auth модуля (MongoDB)
    async with httpx.AsyncClient() as client:
        token = current_user.get("token") or ""
        mongo_id = db_user.auth_id.replace("mongo-", "") if db_user.auth_id and db_user.auth_id.startswith("mongo-") else (db_user.auth_id if db_user.auth_id else "")
        
        if mongo_id:
            try:
                response = await client.delete(
                    f"{os.getenv('AUTH_SERVICE_URL', 'http://auth_module:8080')}/api/v1/users/{mongo_id}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"
                    },
                    timeout=10.0
                )
                
                if response.status_code not in [200, 204]:
                    try:
                        error_data = response.json()
                        error_detail = error_data.get("error", error_data.get("detail", response.text))
                    except:
                        error_detail = response.text or "Auth service error"
                    raise HTTPException(status_code=response.status_code, detail=error_detail)
            except httpx.RequestError as e:
                raise HTTPException(status_code=503, detail=f"Auth service unavailable: {str(e)}")
    
    # Удаляем из PostgreSQL
    db.delete(db_user)
    db.commit()
    
    return {"message": f"User {user_id} deleted successfully"}

@app.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin"))
):
    """Сброс пароля пользователя на "password" (только для админа) - проксирует в auth модуль"""
    import httpx
    
    # Находим пользователя в PostgreSQL
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Обновляем пароль в auth модуле
    async with httpx.AsyncClient() as client:
        token = current_user.get("token") or ""
        mongo_id = db_user.auth_id.replace("mongo-", "") if db_user.auth_id and db_user.auth_id.startswith("mongo-") else (db_user.auth_id if db_user.auth_id else "")
        
        if not mongo_id:
            raise HTTPException(status_code=400, detail="User auth_id not found")
        
        try:
            response = await client.put(
                f"{os.getenv('AUTH_SERVICE_URL', 'http://auth_module:8080')}/api/v1/users/{mongo_id}",
                json={"password": "password"},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            
            if response.status_code != 200:
                try:
                    error_data = response.json()
                    error_detail = error_data.get("error", error_data.get("detail", response.text))
                except:
                    error_detail = response.text or "Auth service error"
                raise HTTPException(status_code=response.status_code, detail=error_detail)
        except httpx.RequestError as e:
            raise HTTPException(status_code=503, detail=f"Auth service unavailable: {str(e)}")
    
    return {"message": f"Password for user {db_user.username} reset to 'password'"}

# Запуск сервера через uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
