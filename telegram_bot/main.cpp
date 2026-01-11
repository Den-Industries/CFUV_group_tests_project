#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <algorithm>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <hiredis/hiredis.h>
#include <thread>
#include <chrono>
#include <regex>

// Configuration
const std::string BOT_TOKEN = "8097020213:AAFTYeWmWules9nMTa2eazDc-r3Q5ZzboMs";
const std::string TELEGRAM_API = "https://api.telegram.org/bot" + BOT_TOKEN;
const std::string AUTH_API = "http://auth_module:8080/api/v1";
const std::string CENTRAL_API = "http://central_module:8000";
const std::string REDIS_HOST = "redis";
const int REDIS_PORT = 6379;

// Test result structure
struct TestResult {
    int score = 0;
    int max_score = 0;
    double percentage = 0.0;
    bool success = false;
};

// User session structure
struct UserSession {
    std::string username;
    std::string token;
    std::string email;
    std::string role;
    int current_test_id = 0;
    std::map<int, int> test_answers; // question_id -> answer_index
    std::string state; // "menu", "login", "code", "tests", "taking_test", "results"
};

// Global session storage (in production, use Redis)
std::map<int64_t, UserSession> user_sessions;

// Forward declarations
void showMainMenu(int64_t chat_id);
void sendTestQuestion(int64_t chat_id, int question_index);
void handleTestSubmit(int64_t chat_id);
void handleStart(int64_t chat_id);
void handleLogin(int64_t chat_id);
void handleCodeAuth(int64_t chat_id);
void handleTestsList(int64_t chat_id);
void handleTestStart(int64_t chat_id, int test_id);
void handleAnswer(int64_t chat_id, int answer_num);
void handleLogout(int64_t chat_id);
void processMessage(int64_t chat_id, const std::string& text);

// HTTP request helper
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* data) {
    size_t totalSize = size * nmemb;
    data->append((char*)contents, totalSize);
    return totalSize;
}

std::string httpGet(const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    
    return response;
}

std::string httpPost(const std::string& url, const std::string& data) {
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    return response;
}

// Redis helper
redisContext* connectRedis() {
    redisContext* c = redisConnect(REDIS_HOST.c_str(), REDIS_PORT);
    if (c == nullptr || c->err) {
        if (c) {
            std::cerr << "Redis connection error: " << c->errstr << std::endl;
            redisFree(c);
        } else {
            std::cerr << "Redis connection error: can't allocate redis context" << std::endl;
        }
        return nullptr;
    }
    return c;
}

void saveSessionToRedis(int64_t chat_id, const UserSession& session) {
    redisContext* c = connectRedis();
    if (c == nullptr) return;
    
    Json::Value sessionJson;
    sessionJson["username"] = session.username;
    sessionJson["token"] = session.token;
    sessionJson["email"] = session.email;
    sessionJson["role"] = session.role;
    sessionJson["current_test_id"] = session.current_test_id;
    sessionJson["state"] = session.state;
    
    Json::StreamWriterBuilder builder;
    std::string sessionStr = Json::writeString(builder, sessionJson);
    
    std::string key = "tg_session:" + std::to_string(chat_id);
    redisReply* reply = (redisReply*)redisCommand(c, "SETEX %s 3600 %s", key.c_str(), sessionStr.c_str());
    
    if (reply) freeReplyObject(reply);
    redisFree(c);
}

UserSession loadSessionFromRedis(int64_t chat_id) {
    UserSession session;
    redisContext* c = connectRedis();
    if (c == nullptr) return session;
    
    std::string key = "tg_session:" + std::to_string(chat_id);
    redisReply* reply = (redisReply*)redisCommand(c, "GET %s", key.c_str());
    
    if (reply && reply->type == REDIS_REPLY_STRING) {
        Json::Reader reader;
        Json::Value sessionJson;
        if (reader.parse(reply->str, sessionJson)) {
            session.username = sessionJson.get("username", "").asString();
            session.token = sessionJson.get("token", "").asString();
            session.email = sessionJson.get("email", "").asString();
            session.role = sessionJson.get("role", "").asString();
            session.current_test_id = sessionJson.get("current_test_id", 0).asInt();
            session.state = sessionJson.get("state", "menu").asString();
            
            // Load test answers
            if (sessionJson.isMember("test_answers")) {
                Json::Value answersJson = sessionJson["test_answers"];
                for (auto it = answersJson.begin(); it != answersJson.end(); ++it) {
                    int question_id = std::stoi(it.key().asString());
                    int answer_index = it->asInt();
                    session.test_answers[question_id] = answer_index;
                }
            }
        }
    }
    
    if (reply) freeReplyObject(reply);
    redisFree(c);
    return session;
}

// Telegram API helpers
void sendMessage(int64_t chat_id, const std::string& text, const std::string& reply_markup = "") {
    std::string url = TELEGRAM_API + "/sendMessage";
    
    Json::Value json;
    json["chat_id"] = (Json::Int64)chat_id;
    json["text"] = text;
    json["parse_mode"] = "HTML";
    
    if (!reply_markup.empty()) {
        Json::Reader reader;
        Json::Value markup;
        if (reader.parse(reply_markup, markup)) {
            json["reply_markup"] = markup;
        }
    }
    
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);
    
    httpPost(url, jsonStr);
}

void sendKeyboard(int64_t chat_id, const std::string& text, const std::vector<std::vector<std::string>>& buttons) {
    Json::Value keyboard;
    Json::Value rows(Json::arrayValue);
    
    for (const auto& row : buttons) {
        Json::Value buttonRow(Json::arrayValue);
        for (const auto& button : row) {
            Json::Value btn;
            btn["text"] = button;
            buttonRow.append(btn);
        }
        rows.append(buttonRow);
    }
    
    keyboard["keyboard"] = rows;
    keyboard["resize_keyboard"] = true;
    keyboard["one_time_keyboard"] = false;
    
    Json::StreamWriterBuilder builder;
    std::string markup = Json::writeString(builder, keyboard);
    
    sendMessage(chat_id, text, markup);
}

// Authentication functions
bool loginUser(int64_t chat_id, const std::string& username, const std::string& password) {
    std::string url = AUTH_API + "/login";
    
    Json::Value json;
    json["username"] = username;
    json["password"] = password;
    
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);
    
    std::string response = httpPost(url, jsonStr);
    
    Json::Reader reader;
    Json::Value responseJson;
    if (reader.parse(response, responseJson)) {
        if (responseJson.isMember("access_token")) {
            UserSession& session = user_sessions[chat_id];
            session.username = username;
            session.token = responseJson["access_token"].asString();
            session.email = responseJson["user"].get("email", "").asString();
            session.role = responseJson["user"].get("role", "user").asString();
            session.state = "menu";
            saveSessionToRedis(chat_id, session);
            return true;
        }
    }
    return false;
}

bool verifyCode(int64_t chat_id, const std::string& email, const std::string& code) {
    std::string url = AUTH_API + "/code/verify";
    
    Json::Value json;
    json["email"] = email;
    json["code"] = code;
    
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);
    
    std::string response = httpPost(url, jsonStr);
    
    Json::Reader reader;
    Json::Value responseJson;
    if (reader.parse(response, responseJson)) {
        if (responseJson.isMember("access_token")) {
            UserSession& session = user_sessions[chat_id];
            session.email = email;
            session.token = responseJson["access_token"].asString();
            session.username = responseJson["user"].get("username", "").asString();
            session.role = responseJson["user"].get("role", "user").asString();
            session.state = "menu";
            saveSessionToRedis(chat_id, session);
            return true;
        }
    }
    return false;
}

// API functions
std::vector<Json::Value> getTests(const std::string& token) {
    std::vector<Json::Value> tests;
    std::string url = CENTRAL_API + "/tests";
    
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        struct curl_slist* headers = nullptr;
        std::string authHeader = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, authHeader.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    Json::Reader reader;
    Json::Value json;
    if (reader.parse(response, json) && json.isArray()) {
        for (const auto& test : json) {
            if (test.get("is_active", true).asBool()) {
                tests.push_back(test);
            }
        }
    }
    
    return tests;
}

Json::Value getTestQuestions(int test_id, const std::string& token) {
    std::string url = CENTRAL_API + "/tests/" + std::to_string(test_id) + "/questions";
    
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        struct curl_slist* headers = nullptr;
        std::string authHeader = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, authHeader.c_str());
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    Json::Reader reader;
    Json::Value json;
    reader.parse(response, json);
    return json;
}

TestResult submitTest(int test_id, const std::map<int, int>& answers, const std::string& token) {
    TestResult result;
    std::string url = CENTRAL_API + "/tests/" + std::to_string(test_id) + "/submit";
    
    Json::Value json;
    Json::Value answersArray(Json::arrayValue);
    
    for (const auto& pair : answers) {
        Json::Value answer;
        answer["question_id"] = pair.first;
        answer["answer_index"] = pair.second;
        answersArray.append(answer);
    }
    
    json["answers"] = answersArray;
    
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);
    
    CURL* curl = curl_easy_init();
    std::string response;
    
    if (curl) {
        struct curl_slist* headers = nullptr;
        std::string authHeader = "Authorization: Bearer " + token;
        headers = curl_slist_append(headers, authHeader.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        
        curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    Json::Reader reader;
    Json::Value responseJson;
    if (reader.parse(response, responseJson) && responseJson.isMember("score")) {
        result.success = true;
        result.score = responseJson.get("score", 0).asInt();
        result.max_score = responseJson.get("max_score", 0).asInt();
        result.percentage = responseJson.get("percentage", 0.0).asDouble();
    }
    
    return result;
}

// Bot handlers
void handleStart(int64_t chat_id) {
    UserSession session = loadSessionFromRedis(chat_id);
    user_sessions[chat_id] = session;
    
    if (session.token.empty()) {
        session.state = "login";
        user_sessions[chat_id] = session;
        
        std::vector<std::vector<std::string>> buttons = {
            {"🔐 Войти по логину и паролю"},
            {"📧 Войти по коду"}
        };
        sendKeyboard(chat_id, 
            "👋 Добро пожаловать в систему тестирования!\n\n"
            "Выберите способ авторизации:",
            buttons);
    } else {
        showMainMenu(chat_id);
    }
}

void showMainMenu(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    session.state = "menu";
    saveSessionToRedis(chat_id, session);
    
    std::vector<std::vector<std::string>> buttons = {
        {"📋 Список тестов"},
        {"🚪 Выйти"}
    };
    
    std::string text = "👤 <b>Главное меню</b>\n\n";
    text += "Пользователь: " + session.username + "\n";
    text += "Email: " + session.email + "\n\n";
    text += "Выберите действие:";
    
    sendKeyboard(chat_id, text, buttons);
}

void handleLogin(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    session.state = "login_username";
    session.username = ""; // Clear previous username
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
    
    sendMessage(chat_id, "Введите ваш логин:");
}

void handleCodeAuth(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    session.state = "code_email";
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
    
    sendMessage(chat_id, "Введите ваш email:");
}

void handleTestsList(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty()) {
        sendMessage(chat_id, "❌ Вы не авторизованы. Используйте /start для входа.");
        return;
    }
    
    auto tests = getTests(session.token);
    
    if (tests.empty()) {
        sendMessage(chat_id, "📭 Нет доступных тестов.");
        return;
    }
    
    std::string text = "📋 <b>Доступные тесты:</b>\n\n";
    std::vector<std::vector<std::string>> buttons;
    
    for (const auto& test : tests) {
        int test_id = test.get("id", 0).asInt();
        std::string title = test.get("title", "").asString();
        text += "📝 " + title + " (ID: " + std::to_string(test_id) + ")\n";
        
        std::vector<std::string> row;
        row.push_back("▶️ Тест " + std::to_string(test_id));
        buttons.push_back(row);
    }
    
    buttons.push_back({"🔙 Назад"});
    
    sendKeyboard(chat_id, text, buttons);
    session.state = "tests";
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
}

void handleTestStart(int64_t chat_id, int test_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty()) {
        sendMessage(chat_id, "❌ Вы не авторизованы.");
        return;
    }
    
    auto questions = getTestQuestions(test_id, session.token);
    
    if (!questions.isArray() || questions.size() == 0) {
        sendMessage(chat_id, "❌ Тест не найден или не содержит вопросов.");
        return;
    }
    
    session.current_test_id = test_id;
    session.test_answers.clear();
    session.state = "taking_test";
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
    
    sendTestQuestion(chat_id, 0);
}

void sendTestQuestion(int64_t chat_id, int question_index) {
    UserSession& session = user_sessions[chat_id];
    
    auto questions = getTestQuestions(session.current_test_id, session.token);
    
    if (!questions.isArray() || question_index >= (int)questions.size()) {
        // Test completed
        handleTestSubmit(chat_id);
        return;
    }
    
    Json::Value question = questions[question_index];
    int question_id = question.get("id", 0).asInt();
    std::string question_text = question.get("question_text", "").asString();
    auto answers = question["answers"];
    
    std::string text = "❓ <b>Вопрос " + std::to_string(question_index + 1) + " из " + std::to_string(questions.size()) + ":</b>\n\n";
    text += question_text + "\n\n";
    text += "<b>Варианты ответов:</b>\n";
    
    std::vector<std::vector<std::string>> buttons;
    int answer_index = 0;
    
    if (answers.isArray()) {
        // Sort answers by order_index
        std::vector<std::pair<int, Json::Value>> sorted_answers;
        for (const auto& answer : answers) {
            int order = answer.get("order_index", answer_index).asInt();
            sorted_answers.push_back({order, answer});
        }
        std::sort(sorted_answers.begin(), sorted_answers.end());
        
        for (const auto& pair : sorted_answers) {
            const auto& answer = pair.second;
            std::string answer_text = answer.get("answer_text", "").asString();
            text += std::to_string(answer_index + 1) + ". " + answer_text + "\n";
            
            std::vector<std::string> row;
            row.push_back(std::to_string(answer_index + 1));
            buttons.push_back(row);
            answer_index++;
        }
    }
    
    buttons.push_back({"✅ Завершить тест"});
    
    sendKeyboard(chat_id, text, buttons);
}

void handleAnswer(int64_t chat_id, int answer_num) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.state != "taking_test") {
        return;
    }
    
    auto questions = getTestQuestions(session.current_test_id, session.token);
    
    if (!questions.isArray()) {
        sendMessage(chat_id, "❌ Ошибка загрузки вопросов.");
        return;
    }
    
    // Find current question index (first unanswered question)
    int current_index = 0;
    int current_question_id = 0;
    
    for (int i = 0; i < (int)questions.size(); i++) {
        Json::Value q = questions[i];
        int q_id = q.get("id", 0).asInt();
        if (session.test_answers.find(q_id) == session.test_answers.end()) {
            current_index = i;
            current_question_id = q_id;
            break;
        }
    }
    
    if (current_question_id > 0) {
        // Store answer (convert from 1-based to 0-based)
        session.test_answers[current_question_id] = answer_num - 1;
        user_sessions[chat_id] = session;
        saveSessionToRedis(chat_id, session);
        
        // Send next question
        sendTestQuestion(chat_id, current_index + 1);
    } else {
        // All questions answered
        handleTestSubmit(chat_id);
    }
}

void handleTestSubmit(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.test_answers.empty()) {
        sendMessage(chat_id, "❌ Вы не ответили ни на один вопрос.");
        showMainMenu(chat_id);
        return;
    }
    
    sendMessage(chat_id, "⏳ Отправка результатов...");
    
    TestResult result = submitTest(session.current_test_id, session.test_answers, session.token);
    
    if (result.success) {
        // Формируем сообщение с результатами
        std::string resultMessage = "✅ <b>Тест завершен!</b>\n\n";
        resultMessage += "📊 <b>Ваши результаты:</b>\n";
        resultMessage += "🎯 Баллы: " + std::to_string(result.score) + " / " + std::to_string(result.max_score) + "\n";
        resultMessage += "📈 Процент правильных ответов: " + std::to_string((int)result.percentage) + "%\n\n";
        
        // Добавляем оценку
        if (result.percentage >= 90) {
            resultMessage += "🏆 <b>Отлично!</b> Вы показали превосходный результат!";
        } else if (result.percentage >= 70) {
            resultMessage += "👍 <b>Хорошо!</b> Вы справились с тестом!";
        } else if (result.percentage >= 50) {
            resultMessage += "📝 <b>Удовлетворительно.</b> Есть над чем поработать.";
        } else {
            resultMessage += "📚 <b>Попробуйте еще раз.</b> Изучите материал и повторите тест.";
        }
        
        resultMessage += "\n\nИспользуйте /menu для возврата в главное меню.";
        
        sendMessage(chat_id, resultMessage);
    } else {
        sendMessage(chat_id, "❌ Ошибка при отправке теста. Попробуйте позже.");
    }
    
    session.current_test_id = 0;
    session.test_answers.clear();
    session.state = "menu";
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
    
    showMainMenu(chat_id);
}

void handleLogout(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    session = UserSession();
    user_sessions[chat_id] = session;
    
    redisContext* c = connectRedis();
    if (c) {
        std::string key = "tg_session:" + std::to_string(chat_id);
        redisReply* reply = (redisReply*)redisCommand(c, "DEL %s", key.c_str());
        if (reply) freeReplyObject(reply);
        redisFree(c);
    }
    
    sendMessage(chat_id, "👋 Вы вышли из системы.");
    handleStart(chat_id);
}

// Message handler
void processMessage(int64_t chat_id, const std::string& text) {
    UserSession& session = user_sessions[chat_id];
    if (session.state.empty()) {
        session = loadSessionFromRedis(chat_id);
        user_sessions[chat_id] = session;
    }
    
    // Handle commands
    if (text == "/start") {
        handleStart(chat_id);
        return;
    }
    
    if (text == "🔙 Назад" || text == "/menu") {
        showMainMenu(chat_id);
        return;
    }
    
    if (text == "🚪 Выйти") {
        handleLogout(chat_id);
        return;
    }
    
    // Handle states
    if (session.state == "login_username") {
        // Store username and ask for password
        session.username = text;
        session.state = "login_password";
        user_sessions[chat_id] = session;
        saveSessionToRedis(chat_id, session);
        sendMessage(chat_id, "Введите ваш пароль:");
        return;
    }
    
    if (session.state == "login_password") {
        // Get username from session and use entered password
        std::string username = session.username;
        if (username.empty()) {
            sendMessage(chat_id, "❌ Ошибка. Начните заново.");
            handleStart(chat_id);
            return;
        }
        
        if (loginUser(chat_id, username, text)) {
            sendMessage(chat_id, "✅ Авторизация успешна!");
            showMainMenu(chat_id);
        } else {
            sendMessage(chat_id, "❌ Неверный логин или пароль. Попробуйте снова.");
            handleLogin(chat_id);
        }
        return;
    }
    
    if (session.state == "code_email") {
        // Store email in session
        session.email = text;
        session.state = "code_input";
        user_sessions[chat_id] = session;
        saveSessionToRedis(chat_id, session);
        
        // Send code request
        std::string url = AUTH_API + "/code/send";
        Json::Value json;
        json["email"] = text;
        Json::StreamWriterBuilder builder;
        std::string jsonStr = Json::writeString(builder, json);
        httpPost(url, jsonStr);
        
        sendMessage(chat_id, "📧 Код отправлен на email. Введите код (демо: 123456):");
        return;
    }
    
    if (session.state == "code_input") {
        // Get email from session
        std::string email = session.email;
        if (email.empty()) {
            sendMessage(chat_id, "❌ Ошибка. Начните заново.");
            handleStart(chat_id);
            return;
        }
        
        if (verifyCode(chat_id, email, text)) {
            sendMessage(chat_id, "✅ Авторизация успешна!");
            showMainMenu(chat_id);
        } else {
            sendMessage(chat_id, "❌ Неверный код. Попробуйте снова.");
            handleCodeAuth(chat_id);
        }
        return;
    }
    
    // Handle menu options
    if (text == "🔐 Войти по логину и паролю") {
        handleLogin(chat_id);
        return;
    }
    
    if (text == "📧 Войти по коду") {
        handleCodeAuth(chat_id);
        return;
    }
    
    if (text == "📋 Список тестов") {
        handleTestsList(chat_id);
        return;
    }
    
    // Handle test selection
    if (session.state == "tests") {
        // Check if text starts with "▶️ Тест " or contains test ID
        if (text.find("Тест ") != std::string::npos || text.find("▶️") != std::string::npos) {
            // Find the last space and extract number after it
            size_t last_space = text.find_last_of(" ");
            if (last_space != std::string::npos && last_space < text.length() - 1) {
                std::string test_id_str = text.substr(last_space + 1);
                try {
                    int test_id = std::stoi(test_id_str);
                    handleTestStart(chat_id, test_id);
                    return;
                } catch (...) {
                    sendMessage(chat_id, "❌ Неверный ID теста: " + test_id_str);
                    return;
                }
            }
        }
    }
    
    // Handle test answers
    if (session.state == "taking_test") {
        if (text == "✅ Завершить тест") {
            handleTestSubmit(chat_id);
            return;
        }
        
        // Try to parse answer number
        try {
            int answer_num = std::stoi(text);
            if (answer_num > 0) {
                handleAnswer(chat_id, answer_num);
                return;
            }
        } catch (...) {
            // Not a number
        }
    }
    
    sendMessage(chat_id, "❓ Не понимаю команду. Используйте /start для начала.");
}

// Webhook handler (for production)
void handleWebhook(const std::string& body) {
    Json::Reader reader;
    Json::Value update;
    
    if (!reader.parse(body, update)) {
        return;
    }
    
    if (update.isMember("message")) {
        Json::Value message = update["message"];
        int64_t chat_id = message["chat"]["id"].asInt64();
        std::string text = message.get("text", "").asString();
        
        if (!text.empty()) {
            processMessage(chat_id, text);
        }
    }
}

// Long polling
void longPoll() {
    int64_t last_update_id = 0;
    
    while (true) {
        std::string url = TELEGRAM_API + "/getUpdates?offset=" + std::to_string(last_update_id + 1) + "&timeout=10";
        std::string response = httpGet(url);
        
        Json::Reader reader;
        Json::Value json;
        
        if (reader.parse(response, json) && json.get("ok", false).asBool()) {
            Json::Value updates = json["result"];
            
            for (const auto& update : updates) {
                last_update_id = update.get("update_id", 0).asInt64();
                
                if (update.isMember("message")) {
                    Json::Value message = update["message"];
                    int64_t chat_id = message["chat"]["id"].asInt64();
                    std::string text = message.get("text", "").asString();
                    
                    if (!text.empty()) {
                        processMessage(chat_id, text);
                    }
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    std::cout << "Telegram Bot started..." << std::endl;
    
    // Test Redis connection
    redisContext* c = connectRedis();
    if (c) {
        std::cout << "Redis connected successfully" << std::endl;
        redisFree(c);
    } else {
        std::cout << "Warning: Redis connection failed, continuing without Redis" << std::endl;
    }
    
    // Start long polling
    longPoll();
    
    curl_global_cleanup();
    return 0;
}
