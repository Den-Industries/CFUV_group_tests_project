-- Удаляем уникальное ограничение на username
ALTER TABLE survey.users DROP CONSTRAINT IF EXISTS users_username_key;

-- Добавляем индекс для быстрого поиска по username
CREATE INDEX idx_users_username ON survey.users(username);

-- Проверяем текущих пользователей
SELECT * FROM survey.users;
