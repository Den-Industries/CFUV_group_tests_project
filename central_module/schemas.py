from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    role: str

class TestCreate(BaseModel):
    title: str
    description: Optional[str] = None

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
    answers: List[Dict[str, Any]]

class ResultCreate(BaseModel):
    test_id: int
    answers: List[Dict[str, Any]]

class AnswerCreate(BaseModel):
    answer_text: str
    is_correct: bool = False

class QuestionResponse(BaseModel):
    id: int
    test_id: int
    question_text: str
    question_type: str
    points: int
    answers: List[Dict[str, Any]]

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str]
    role: str

class TokenData(BaseModel):
    access_token: str
    token_type: str
