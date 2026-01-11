from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    auth_id = Column(String(100), unique=True, index=True, nullable=False)
    username = Column(String(50), index=True, nullable=False)
    email = Column(String(100))
    password_hash = Column(String(255), nullable=True)  # Новое поле (nullable для совместимости)
    role = Column(String(20), default='user')
    last_login = Column(DateTime(timezone=True), nullable=True)  # Новое поле
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    tests = relationship("Test", back_populates="creator")
    results = relationship("Result", back_populates="user")

class Test(Base):
    __tablename__ = "tests"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    created_by = Column(Integer, ForeignKey('survey.users.id'))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    creator = relationship("User", back_populates="tests")
    questions = relationship("Question", back_populates="test", cascade="all, delete-orphan")
    results = relationship("Result", back_populates="test")

class Question(Base):
    __tablename__ = "questions"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey('survey.tests.id'))
    question_text = Column(Text, nullable=False)
    question_type = Column(String(20), default='single_choice')
    order_index = Column(Integer, default=0)
    points = Column(Integer, default=1)
    
    test = relationship("Test", back_populates="questions")
    answers = relationship("Answer", back_populates="question", cascade="all, delete-orphan")

class Answer(Base):
    __tablename__ = "answers"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    question_id = Column(Integer, ForeignKey('survey.questions.id'))
    answer_text = Column(Text, nullable=False)
    is_correct = Column(Boolean, default=False)
    order_index = Column(Integer, default=0)
    
    question = relationship("Question", back_populates="answers")

class Result(Base):
    __tablename__ = "results"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('survey.users.id'))
    test_id = Column(Integer, ForeignKey('survey.tests.id'))
    score = Column(Integer, default=0)
    max_score = Column(Integer, default=0)
    completed_at = Column(DateTime(timezone=True), server_default=func.now())
    answers_data = Column(JSON)
    
    user = relationship("User", back_populates="results")
    test = relationship("Test", back_populates="results")
    user_answers = relationship("UserAnswer", back_populates="result", cascade="all, delete-orphan")

class UserAnswer(Base):
    __tablename__ = "user_answers"
    __table_args__ = {'schema': 'survey'}
    
    id = Column(Integer, primary_key=True, index=True)
    result_id = Column(Integer, ForeignKey('survey.results.id'))
    question_id = Column(Integer, ForeignKey('survey.questions.id'))
    answer_id = Column(Integer, ForeignKey('survey.answers.id'))
    answer_text = Column(Text)
    is_correct = Column(Boolean, default=False)
    points_earned = Column(Integer, default=0)
    
    result = relationship("Result", back_populates="user_answers")
