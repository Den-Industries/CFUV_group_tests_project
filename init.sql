-- Создание схемы для центрального модуля
CREATE SCHEMA IF NOT EXISTS survey;

-- Пользователи (синхронизируется с auth модулем)
CREATE TABLE IF NOT EXISTS survey.users (
    id SERIAL PRIMARY KEY,
    auth_id VARCHAR(100) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Тесты
CREATE TABLE IF NOT EXISTS survey.tests (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    created_by INTEGER REFERENCES survey.users(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Вопросы
CREATE TABLE IF NOT EXISTS survey.questions (
    id SERIAL PRIMARY KEY,
    test_id INTEGER NOT NULL REFERENCES survey.tests(id) ON DELETE CASCADE,
    question_text TEXT NOT NULL,
    question_type VARCHAR(20) DEFAULT 'single_choice',
    order_index INTEGER DEFAULT 0,
    points INTEGER DEFAULT 1
);

-- Варианты ответов
CREATE TABLE IF NOT EXISTS survey.answers (
    id SERIAL PRIMARY KEY,
    question_id INTEGER NOT NULL REFERENCES survey.questions(id) ON DELETE CASCADE,
    answer_text TEXT NOT NULL,
    is_correct BOOLEAN DEFAULT false,
    order_index INTEGER DEFAULT 0
);

-- Результаты тестирования
CREATE TABLE IF NOT EXISTS survey.results (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES survey.users(id),
    test_id INTEGER NOT NULL REFERENCES survey.tests(id),
    score INTEGER DEFAULT 0,
    max_score INTEGER DEFAULT 0,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    answers_data JSONB -- Хранение ответов пользователя
);

-- Ответы пользователей
CREATE TABLE IF NOT EXISTS survey.user_answers (
    id SERIAL PRIMARY KEY,
    result_id INTEGER NOT NULL REFERENCES survey.results(id) ON DELETE CASCADE,
    question_id INTEGER NOT NULL REFERENCES survey.questions(id),
    answer_id INTEGER REFERENCES survey.answers(id),
    answer_text TEXT,
    is_correct BOOLEAN DEFAULT false,
    points_earned INTEGER DEFAULT 0
);

-- Индексы для оптимизации
CREATE INDEX idx_users_auth_id ON survey.users(auth_id);
CREATE INDEX idx_tests_created_by ON survey.tests(created_by);
CREATE INDEX idx_questions_test_id ON survey.questions(test_id);
CREATE INDEX idx_results_user_test ON survey.results(user_id, test_id);
CREATE INDEX idx_user_answers_result ON survey.user_answers(result_id);

-- Вставляем тестовые данные
INSERT INTO survey.users (auth_id, username, email, role) VALUES
('admin-123', 'admin', 'admin@survey.local', 'admin'),
('user-456', 'testuser', 'user@survey.local', 'user')
ON CONFLICT (auth_id) DO NOTHING;

-- Обновляем схему базы данных
ALTER TABLE survey.users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE survey.users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP;

-- Убедимся, что пароль установлен
SELECT id, username, email, role, password_hash IS NOT NULL as has_password FROM survey.users;
