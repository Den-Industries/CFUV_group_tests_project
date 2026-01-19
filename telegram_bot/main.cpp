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
//Конфигурации
static std::string BOT_TOKEN;
static std::string TELEGRAM_API;
static std::string AUTH_API = "http://auth_module:8080/api/auth";
static std::string CENTRAL_API = "http://central_module:8000/api/central";
static std::string REDIS_HOST = "redis";
static int REDIS_PORT = 6379;

//Функция для безопасного получения значения переменной окружения
static std::string getenvOrDefault(const char* key, const std::string& def) {
    const char* v = std::getenv(key);
    if (!v || std::string(v).empty()) return def;
    return std::string(v);
}
//Функция инициализации конфигурации приложения
static void initConfig() {
    BOT_TOKEN = getenvOrDefault("TELEGRAM_BOT_TOKEN", "");
    if (BOT_TOKEN.empty()) {
        std::cerr << "TELEGRAM_BOT_TOKEN is not set. Bot cannot start." << std::endl;
        std::exit(1);
    }
    TELEGRAM_API = "https://api.telegram.org/bot" + BOT_TOKEN;

    AUTH_API = getenvOrDefault("AUTH_API", AUTH_API);
    CENTRAL_API = getenvOrDefault("CENTRAL_API", CENTRAL_API);
    
    //Конфигурации редиса
    std::string redisUrl = getenvOrDefault("REDIS_URL", "redis://redis:6379");
    const std::string prefix = "redis://";
    if (redisUrl.rfind(prefix, 0) == 0) {
        std::string hostPort = redisUrl.substr(prefix.size());
        auto colon = hostPort.find(':');
        if (colon != std::string::npos) {
            REDIS_HOST = hostPort.substr(0, colon);
            try { REDIS_PORT = std::stoi(hostPort.substr(colon + 1)); } catch (...) {}
        } else {
            REDIS_HOST = hostPort;
        }
    }
}

//Структура для хранения результатов теста
struct TestResult {
    int score = 0;
    int max_score = 0;
    double percentage = 0.0;
    bool success = false;
};
//Структура для хранения сессии пользователя
struct UserSession {
    std::string username;
    std::string token;
    std::string refresh_token;
    std::string email;
    std::string role;
    int current_test_id = 0;
    std::map<int, int> test_answers;
    std::string state;
    std::string device_code; 
    time_t code_expires = 0;
};

//Глобальное хранилище сессий
std::map<int64_t, UserSession> user_sessions;
std::map<std::string, int64_t> device_code_to_chat;

//Предварительные обьявления функций
void showMainMenu(int64_t chat_id);
void sendTestQuestion(int64_t chat_id, int question_index);
void handleTestSubmit(int64_t chat_id);
void handleStart(int64_t chat_id);
void handleDeviceCodeLogin(int64_t chat_id);
void handleTestsList(int64_t chat_id);
void handleTestStart(int64_t chat_id, int test_id);
void handleAnswer(int64_t chat_id, int answer_num);
void handleLogout(int64_t chat_id);
void processMessage(int64_t chat_id, const std::string& text);
void saveSessionToRedis(int64_t chat_id, const UserSession& session);
UserSession loadSessionFromRedis(int64_t chat_id);
void startDeviceCodePolling(const std::string& code, int64_t chat_id);
void stopDeviceCodePolling(int64_t chat_id);
void checkDeviceCodeStatus(int64_t chat_id);
void approveDeviceCode(int64_t chat_id);
//HTTP
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* data) {
    size_t totalSize = size * nmemb;
    data->append((char*)contents, totalSize);
    return totalSize;
}

//Структура и функция для HTTP запросов с обработкой ответов
struct HttpResponse {
    long status = 0;
    std::string body;
};

HttpResponse httpRequest(const std::string& url, const std::string& method = "GET", 
                         const std::string& body = "", const std::string& bearerToken = "") {
    HttpResponse out;
    CURL* curl = curl_easy_init();
    if (!curl) return out;

    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!bearerToken.empty()) {
        std::string authHeader = "Authorization: Bearer " + bearerToken;
        headers = curl_slist_append(headers, authHeader.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.status);
        out.body = response;
    } else {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return out;
}
//Управление токенами
bool refreshAccessToken(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    if (session.refresh_token.empty()) return false;

    Json::Value json;
    json["refresh_token"] = session.refresh_token;
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);

    HttpResponse resp = httpRequest(AUTH_API + "/refresh", "POST", jsonStr);
    if (resp.status != 200) {
        return false;
    }

    Json::Reader reader;
    Json::Value data;
    if (!reader.parse(resp.body, data) || !data.isMember("access_token")) {
        return false;
    }

    session.token = data["access_token"].asString();
    if (data.isMember("refresh_token")) {
        session.refresh_token = data["refresh_token"].asString();
    }
    if (data.isMember("user")) {
        session.username = data["user"].get("username", "").asString();
        session.email = data["user"].get("email", "").asString();
        session.role = data["user"].get("role", "user").asString();
    }
    saveSessionToRedis(chat_id, session);
    return true;
}

bool verifyAccessToken(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    if (session.token.empty()) return false;

    Json::Value json;
    json["token"] = session.token;
    Json::StreamWriterBuilder builder;
    std::string jsonStr = Json::writeString(builder, json);

    HttpResponse resp = httpRequest(AUTH_API + "/verify", "POST", jsonStr);
    if (resp.status != 200) return false;

    Json::Reader reader;
    Json::Value data;
    if (!reader.parse(resp.body, data)) return false;
    
    if (data.get("valid", false).asBool() && data.isMember("user")) {//Обновляем инфу о пользователе
        session.username = data["user"].get("username", "").asString();
        session.email = data["user"].get("email", "").asString();
        session.role = data["user"].get("role", "user").asString();
        saveSessionToRedis(chat_id, session);
        return true;
    }
    return false;
}
//Функции для подключения к редис серверу
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
    sessionJson["refresh_token"] = session.refresh_token;
    sessionJson["email"] = session.email;
    sessionJson["role"] = session.role;
    sessionJson["current_test_id"] = session.current_test_id;
    sessionJson["state"] = session.state;
    sessionJson["device_code"] = session.device_code;
    sessionJson["code_expires"] = (Json::Int64)session.code_expires;
    
    //Сохраняем ответы в тесте
    Json::Value answersJson(Json::objectValue);
    for (const auto& pair : session.test_answers) {
        answersJson[std::to_string(pair.first)] = pair.second;
    }
    sessionJson["test_answers"] = answersJson;
    
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
            session.refresh_token = sessionJson.get("refresh_token", "").asString();
            session.email = sessionJson.get("email", "").asString();
            session.role = sessionJson.get("role", "").asString();
            session.current_test_id = sessionJson.get("current_test_id", 0).asInt();
            session.state = sessionJson.get("state", "menu").asString();
            session.device_code = sessionJson.get("device_code", "").asString();
            session.code_expires = sessionJson.get("code_expires", 0).asInt64();            
            //Загрузка ответов на тесты
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
//Утилиты для работы с API тг
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
    
    httpRequest(url, "POST", jsonStr);
}

void sendKeyboard(int64_t chat_id, const std::string& text, 
                  const std::vector<std::vector<std::string>>& buttons) {
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
//Функции авторизации по коду, реализация авторизации
void handleDeviceCodeLogin(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    HttpResponse resp = httpRequest(AUTH_API + "/device-code/start", "POST");//Получить код для авторизации на сайте
    
    if (resp.status != 200) {
        sendMessage(chat_id, "❌ Ошибка при получении кода. Попробуйте позже.");
        return;
    }
    
    Json::Reader reader;
    Json::Value data;
    if (!reader.parse(resp.body, data) || !data.isMember("code")) {
        sendMessage(chat_id, "❌ Неверный ответ от сервера.");
        return;
    }
    
    std::string code = data["code"].asString();
    int expires_in = data.get("expires_in", 300).asInt();
    
//Сохранить код в сессии
    session.device_code = code;
    session.code_expires = time(nullptr) + expires_in;
    session.state = "device_code";
    user_sessions[chat_id] = session;
    saveSessionToRedis(chat_id, session);
    
//Регистрация для опроса статуса
    device_code_to_chat[code] = chat_id;
    
    std::string message = "🔐 <b>Код для входа:</b>\n\n";
    message += "<code>" + code + "</code>\n\n";
    message += "📱 <b>Как использовать:</b>\n";
    message += "1. Откройте веб-версию сервиса\n";
    message += "2. Войдите под своей учетной записью\n";
    message += "3. В меню выберите 'Подтвердить код'\n";
    message += "4. Введите этот код\n\n";
    message += "⏰ Код действует " + std::to_string(expires_in / 60) + " минут\n";
    message += "⌛️ Я буду проверять подтверждение автоматически...";
    
    std::vector<std::vector<std::string>> buttons = {
        {"🔄 Проверить сейчас"},
        {"❌ Отменить вход"}
    };
    
    sendKeyboard(chat_id, message, buttons);
    
//Запускаем фоновую проверку статуса кодом
    startDeviceCodePolling(code, chat_id);
}

void startDeviceCodePolling(const std::string& code, int64_t chat_id) {
    //Запускаем опрос в фоновом потоке
    std::thread([code, chat_id]() {
        for (int i = 0; i < 300; i++) { //Опрос 5 мин(300 с)
            std::this_thread::sleep_for(std::chrono::seconds(3));
            
            //Проверка действитетельности кода
            auto it = device_code_to_chat.find(code);
            if (it == device_code_to_chat.end() || it->second != chat_id) {
                break; ////Код больше не действителен
            }
            
            //Опрашиваем сервер
            HttpResponse resp = httpRequest(AUTH_API + "/device-code/poll?code=" + code);
            
            if (resp.status == 404 || resp.status == 410) {
                //Код устарел или не действителен
                sendMessage(chat_id, "❌ Код истёк или недействителен. Начните заново.");
                device_code_to_chat.erase(code);
                
                UserSession session = user_sessions[chat_id];
                if (session.device_code == code) {
                    session.device_code.clear();
                    session.state = "menu";
                    user_sessions[chat_id] = session;
                    saveSessionToRedis(chat_id, session);
                }
                break;
            }
            
            if (resp.status == 200) {
                Json::Reader reader;
                Json::Value data;
                if (reader.parse(resp.body, data) && data.isMember("access_token")) {
                    //Авторизация прошла успешно теперь сохраняем токены
                    UserSession& session = user_sessions[chat_id];
                    session.token = data["access_token"].asString();
                    session.refresh_token = data.get("refresh_token", "").asString();
                    session.username = data["user"].get("username", "").asString();
                    session.email = data["user"].get("email", "").asString();
                    session.role = data["user"].get("role", "user").asString();
                    session.device_code.clear();
                    session.state = "menu";
                    
                    saveSessionToRedis(chat_id, session);
                    device_code_to_chat.erase(code);
                    
                    sendMessage(chat_id, "✅ Авторизация успешна! Добро пожаловать, " + session.username + "!");
                    showMainMenu(chat_id);
                    break;
                }
            }
        }
    }).detach();
}

void stopDeviceCodePolling(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    if (!session.device_code.empty()) {
        device_code_to_chat.erase(session.device_code);
        session.device_code.clear();
        session.state = "menu";
        saveSessionToRedis(chat_id, session);
    }
}

void checkDeviceCodeStatus(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    if (session.device_code.empty()) {
        sendMessage(chat_id, "❌ Нет активного кода для проверки.");
        return;
    }
    
    if (time(nullptr) > session.code_expires) {
        sendMessage(chat_id, "❌ Код истёк. Получите новый код.");
        stopDeviceCodePolling(chat_id);
        return;
    }
    
    sendMessage(chat_id, "⌛️ Проверяю статус кода...");
    
    HttpResponse resp = httpRequest(AUTH_API + "/device-code/poll?code=" + session.device_code);
    
    if (resp.status == 202) {
        sendMessage(chat_id, "⏳ Код ещё не подтверждён. Пожалуйста, подождите...");
    } else if (resp.status == 404 || resp.status == 410) {
        sendMessage(chat_id, "❌ Код истёк или недействителен. Получите новый код.");
        stopDeviceCodePolling(chat_id);
    } else if (resp.status == 200) {
        Json::Reader reader;
        Json::Value data;
        if (reader.parse(resp.body, data) && data.isMember("access_token")) {
            session.token = data["access_token"].asString();
            session.refresh_token = data.get("refresh_token", "").asString();
            session.username = data["user"].get("username", "").asString();
            session.email = data["user"].get("email", "").asString();
            session.role = data["user"].get("role", "user").asString();
            session.device_code.clear();
            session.state = "menu";
            
            saveSessionToRedis(chat_id, session);
            device_code_to_chat.erase(session.device_code);
            
            sendMessage(chat_id, "✅ Авторизация успешна! Добро пожаловать, " + session.username + "!");
            showMainMenu(chat_id);
        }
    } else {
        sendMessage(chat_id, "⚠️ Не удалось проверить статус. Попробуйте позже.");
    }
}

void approveDeviceCode(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty()) {
        sendMessage(chat_id, "❌ Для подтверждения кодов нужно быть авторизованным.");
        return;
    }
    
    sendMessage(chat_id, "Введите код, который показан на другом устройстве:");
    session.state = "approve_code_input";
    saveSessionToRedis(chat_id, session);
}

//Работа с API системы тестирования функции для взаимодействия с центральным сервисом тестов
std::vector<Json::Value> getTests(const std::string& token) {
    std::vector<Json::Value> tests;
    
    HttpResponse resp = httpRequest(CENTRAL_API + "/tests", "GET", "", token);
    
    Json::Reader reader;
    Json::Value json;
    if (reader.parse(resp.body, json) && json.isArray()) {
        for (const auto& test : json) {
            if (test.get("is_active", true).asBool()) {
                tests.push_back(test);
            }
        }
    }
    
    return tests;
}

Json::Value getTestQuestions(int test_id, const std::string& token) {
    HttpResponse resp = httpRequest(CENTRAL_API + "/tests/" + std::to_string(test_id) + "/questions", 
                                   "GET", "", token);
    
    Json::Reader reader;
    Json::Value json;
    reader.parse(resp.body, json);
    return json;
}

TestResult submitTest(int test_id, const std::map<int, int>& answers, const std::string& token) {
    TestResult result;
    
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
    
    HttpResponse resp = httpRequest(CENTRAL_API + "/tests/" + std::to_string(test_id) + "/submit",
                                   "POST", jsonStr, token);
    
    Json::Reader reader;
    Json::Value responseJson;
    if (reader.parse(resp.body, responseJson) && responseJson.isMember("score")) {
        result.success = true;
        result.score = responseJson.get("score", 0).asInt();
        result.max_score = responseJson.get("max_score", 0).asInt();
        result.percentage = responseJson.get("percentage", 0.0).asDouble();
    }
    
    return result;
}

//Обработка команд бота функции для обработки действий пользователя
void handleStart(int64_t chat_id) {
    UserSession session = loadSessionFromRedis(chat_id);
    user_sessions[chat_id] = session;
    
    if (session.token.empty() || !verifyAccessToken(chat_id)) {
        //Пользователь не авторизован
        std::vector<std::vector<std::string>> buttons = {
            {"🔐 Войти по device-code"},
            {"ℹ️ Помощь"}
        };
        
        std::string message = "👋 <b>Добро пожаловать в систему тестирования!</b>\n\n";
        message += "Для доступа к тестам необходимо авторизоваться.\n";
        message += "Используйте device-code авторизацию:\n";
        message += "1. Получите код здесь\n";
        message += "2. Откройте веб-версию сервиса\n";
        message += "3. Подтвердите код в веб-интерфейсе\n\n";
        message += "Выберите действие:";
        
        sendKeyboard(chat_id, message, buttons);
        session.state = "menu";
        saveSessionToRedis(chat_id, session);
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
        {"✅ Подтвердить чужой код"},
        {"🚪 Выйти"}
    };
    
    std::string text = "👤 <b>Главное меню</b>\n\n";
    text += "Пользователь: " + session.username + "\n";
    text += "Email: " + session.email + "\n";
    text += "Роль: " + session.role + "\n\n";
    text += "Выберите действие:";
    
    sendKeyboard(chat_id, text, buttons);
}

void handleTestsList(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty() || !verifyAccessToken(chat_id)) {
        if (!refreshAccessToken(chat_id)) {
            sendMessage(chat_id, "❌ Сессия истекла. Пожалуйста, войдите заново.");
            handleStart(chat_id);
            return;
        }
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
        std::string description = test.get("description", "").asString();
        
        text += "📝 <b>" + title + "</b> (ID: " + std::to_string(test_id) + ")\n";
        if (!description.empty()) {
            text += description + "\n";
        }
        text += "\n";
        
        buttons.push_back({"▶️ Тест " + std::to_string(test_id)});
    }
    
    buttons.push_back({"🔙 Назад"});
    
    sendKeyboard(chat_id, text, buttons);
    session.state = "tests";
    saveSessionToRedis(chat_id, session);
}

void handleTestStart(int64_t chat_id, int test_id) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty() || !verifyAccessToken(chat_id)) {
        if (!refreshAccessToken(chat_id)) {
            sendMessage(chat_id, "❌ Сессия истекла. Пожалуйста, войдите заново.");
            handleStart(chat_id);
            return;
        }
    }
    
    auto questions = getTestQuestions(test_id, session.token);
    
    if (!questions.isArray() || questions.size() == 0) {
        sendMessage(chat_id, "❌ Тест не найден или не содержит вопросов.");
        return;
    }
    
    session.current_test_id = test_id;
    session.test_answers.clear();
    session.state = "taking_test";
    saveSessionToRedis(chat_id, session);
    
    sendTestQuestion(chat_id, 0);
}

void sendTestQuestion(int64_t chat_id, int question_index) {
    UserSession& session = user_sessions[chat_id];
    
    if (session.token.empty() || !verifyAccessToken(chat_id)) {
        if (!refreshAccessToken(chat_id)) {
            sendMessage(chat_id, "❌ Сессия истекла. Пожалуйста, войдите заново.");
            handleStart(chat_id);
            return;
        }
    }
    
    auto questions = getTestQuestions(session.current_test_id, session.token);
    
    if (!questions.isArray() || question_index >= (int)questions.size()) {
        handleTestSubmit(chat_id);
        return;
    }
    
    Json::Value question = questions[question_index];
    int question_id = question.get("id", 0).asInt();
    std::string question_text = question.get("question_text", "").asString();
    auto answers = question["answers"];
    
    std::string text = "❓ <b>Вопрос " + std::to_string(question_index + 1) + " из " + 
                       std::to_string(questions.size()) + ":</b>\n\n";
    text += question_text + "\n\n";
    text += "<b>Варианты ответов:</b>\n";
    
    std::vector<std::vector<std::string>> buttons;
    int answer_index = 0;
    
    if (answers.isArray()) {
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
            
            buttons.push_back({std::to_string(answer_index + 1)});
            answer_index++;
        }
    }
    
    buttons.push_back({"✅ Завершить тест"});
    buttons.push_back({"🔙 Отменить тест"});
    
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
    
    //Ищем текущий вопрос без ответа
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
        session.test_answers[current_question_id] = answer_num - 1;
        saveSessionToRedis(chat_id, session);
        
        sendTestQuestion(chat_id, current_index + 1);
    } else {
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
    
    if (session.token.empty() || !verifyAccessToken(chat_id)) {
        if (!refreshAccessToken(chat_id)) {
            sendMessage(chat_id, "❌ Сессия истекла. Пожалуйста, войдите заново.");
            handleStart(chat_id);
            return;
        }
    }
    
    TestResult result = submitTest(session.current_test_id, session.test_answers, session.token);
    
    if (result.success) {
        std::string resultMessage = "✅ <b>Тест завершен!</b>\n\n";
        resultMessage += "📊 <b>Ваши результаты:</b>\n";
        resultMessage += "🎯 Баллы: " + std::to_string(result.score) + " / " + 
                         std::to_string(result.max_score) + "\n";
        resultMessage += "📈 Процент правильных ответов: " + 
                         std::to_string((int)result.percentage) + "%\n\n";
        
        if (result.percentage >= 90) {
            resultMessage += "🏆 <b>Отлично!</b> Вы показали превосходный результат!";
        } else if (result.percentage >= 70) {
            resultMessage += "👍 <b>Хорошо!</b> Вы справились с тестом!";
        } else if (result.percentage >= 50) {
            resultMessage += "📝 <b>Удовлетворительно.</b> Есть над чем поработать.";
        } else {
            resultMessage += "📚 <b>Попробуйте еще раз.</b> Изучите материал и повторите тест.";
        }
        
        sendMessage(chat_id, resultMessage);
    } else {
        sendMessage(chat_id, "❌ Ошибка при отправке теста. Попробуйте позже.");
    }
    
    session.current_test_id = 0;
    session.test_answers.clear();
    session.state = "menu";
    saveSessionToRedis(chat_id, session);
    
    showMainMenu(chat_id);
}

void handleLogout(int64_t chat_id) {
    UserSession& session = user_sessions[chat_id];
    
    //Остановить все активные проверки кодов устройств
    stopDeviceCodePolling(chat_id);
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

//Проверяем является ли сообщение одной из системных команд
void processMessage(int64_t chat_id, const std::string& text) {
    UserSession& session = user_sessions[chat_id];
    if (session.state.empty()) {
        session = loadSessionFromRedis(chat_id);
        user_sessions[chat_id] = session;
    }
    
    if (text == "/start" || text == "🔙 Назад" || text == "/menu") {
        if (text == "/start") {
            handleStart(chat_id);
        } else {
            showMainMenu(chat_id);
        }
        return;
    }
    
    if (text == "🚪 Выйти") {
        handleLogout(chat_id);
        return;
    }
    
//Проверяем находится ли пользователь в состоянии ожидания ввода кода для подтверждения
    if (session.state == "approve_code_input") {
        std::string code = text;
        
        Json::Value json;
        json["code"] = code;
        Json::StreamWriterBuilder builder;
        std::string jsonStr = Json::writeString(builder, json);
        
        HttpResponse resp = httpRequest(AUTH_API + "/device-code/approve", 
                                       "POST", jsonStr, session.token);
        
        if (resp.status == 200) {
            sendMessage(chat_id, "✅ Код успешно подтверждён. Устройство может войти в систему.");
        } else {
            Json::Reader reader;
            Json::Value errorJson;
            std::string errorMsg = "❌ Ошибка подтверждения кода";
            if (reader.parse(resp.body, errorJson) && errorJson.isMember("error")) {
                errorMsg += ": " + errorJson["error"].asString();
            }
            sendMessage(chat_id, errorMsg);
        }
        
        session.state = "menu";
        saveSessionToRedis(chat_id, session);
        showMainMenu(chat_id);
        return;
    }
    
//Обработка кнопок в меню
    if (text == "🔐 Войти по device-code") {
        handleDeviceCodeLogin(chat_id);
        return;
    }
    
    if (text == "✅ Подтвердить чужой код") {
        approveDeviceCode(chat_id);
        return;
    }
    
    if (text == "🔄 Проверить сейчас") {
        if (session.state == "device_code") {
            checkDeviceCodeStatus(chat_id);
        } else {
            sendMessage(chat_id, "❌ Нет активного кода для проверки.");
        }
        return;
    }
    
    if (text == "❌ Отменить вход") {
        stopDeviceCodePolling(chat_id);
        sendMessage(chat_id, "❌ Вход отменён.");
        handleStart(chat_id);
        return;
    }
    
    if (text == "📋 Список тестов") {
        handleTestsList(chat_id);
        return;
    }
    
    if (text == "👑 Админ-панель") {
        sendMessage(chat_id, "⚙️ Админ-панель находится в разработке...");
        return;
    }
    
    if (text == "ℹ️ Помощь") {
        std::string help = "📖 <b>Справка по боту</b>\n\n";
        help += "Этот бот позволяет проходить тесты после авторизации.\n\n";
        help += "<b>Авторизация:</b>\n";
        help += "1. Нажмите '🔐 Войти по device-code'\n";
        help += "2. Получите код\n";
        help += "3. Откройте веб-версию сервиса\n";
        help += "4. Войдите там под своей учетной записью\n";
        help += "5. В меню выберите 'Подтвердить код'\n";
        help += "6. Введите полученный код\n\n";
        help += "<b>Команды:</b>\n";
        help += "/start - Начать работу\n";
        help += "/menu - Главное меню\n";
        help += "🔙 Назад - Вернуться назад\n\n";
        help += "Бот автоматически проверяет подтверждение кода каждые 3 секунды.";
        sendMessage(chat_id, help);
        return;
    }
    
//Обработка выбора теста 
    if (session.state == "tests") {
        if (text.find("Тест ") != std::string::npos || text.find("▶️") != std::string::npos) {
            size_t last_space = text.find_last_of(" ");
            if (last_space != std::string::npos && last_space < text.length() - 1) {
                std::string test_id_str = text.substr(last_space + 1);
                try {
                    int test_id = std::stoi(test_id_str);
                    handleTestStart(chat_id, test_id);
                    return;
                } catch (...) {
                    sendMessage(chat_id, "❌ Неверный ID теста.");
                    return;
                }
            }
        }
    }
    
//Обработка ответов на тест когда пользователь проходит тест
    if (session.state == "taking_test") {
        if (text == "✅ Завершить тест") {
            handleTestSubmit(chat_id);
            return;
        }
        
        if (text == "🔙 Отменить тест") {
            sendMessage(chat_id, "❌ Тест отменён.");
            session.current_test_id = 0;
            session.test_answers.clear();
            session.state = "menu";
            saveSessionToRedis(chat_id, session);
            showMainMenu(chat_id);
            return;
        }
        //Пользователь тыкнул кнопку с номером ответа
        try {
            int answer_num = std::stoi(text);
            if (answer_num > 0) {
                handleAnswer(chat_id, answer_num);
                return;
            }
        } catch (...) {//Это не номер ответа
            
        }
    }
    
    if (session.token.empty()) {
        std::vector<std::vector<std::string>> buttons = {
            {"🔐 Войти по device-code"},
            {"ℹ️ Помощь"}
        };
        sendKeyboard(chat_id, "Для начала работы необходимо авторизоваться:", buttons);
    } else {
        showMainMenu(chat_id);//Если авторизован, но команда не распознана - показываем главное меню
    }
}

//Бесконечный цикл опроса тг API
void longPoll() {
    int64_t last_update_id = 0;
    
    while (true) {
        std::string url = TELEGRAM_API + "/getUpdates?offset=" + 
                         std::to_string(last_update_id + 1) + "&timeout=10";
        HttpResponse resp = httpRequest(url);
        
        if (resp.status != 200) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        
        Json::Reader reader;
        Json::Value json;
        
        if (reader.parse(resp.body, json) && json.get("ok", false).asBool()) {
            Json::Value updates = json["result"];
            
            for (const auto& update : updates) {
                last_update_id = update.get("update_id", 0).asInt64();
                
                if (update.isMember("message")) {
                    Json::Value message = update["message"];
                    int64_t chat_id = message["chat"]["id"].asInt64();
                    
                    if (message.isMember("text")) {
                        std::string text = message["text"].asString();
                        std::cout << "Processing message from " << chat_id << ": " << text << std::endl;
                        processMessage(chat_id, text);
                    }
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {
    std::cout << "🚀 Запуск Telegram бота с device-code авторизацией..." << std::endl;
    
    //Инициализация конфигурации (загрузка настроек из переменных окружения)
    initConfig();
    
    //Инициализация CURL (подготовка библиотеки для HTTP запросов)
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Проверка соединения редиса
    redisContext* redis = connectRedis();
    if (redis) {
        std::cout << "✅ Redis подключен успешно" << std::endl;
        redisFree(redis);
    } else {
        std::cout << "⚠️ Redis не подключен, бот будет использовать память" << std::endl;
    }
    
    std::cout << "🤖 Бот запущен и готов к работе!" << std::endl;
    std::cout << "Auth API: " << AUTH_API << std::endl;
    std::cout << "Central API: " << CENTRAL_API << std::endl;
    
//Запуск
    longPoll();
    
    curl_global_cleanup();
    return 0;
}
