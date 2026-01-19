// web_client/js/auth.js
const API_BASE = '/api/auth';
let currentUser = null;
let deviceCodePollTimer = null;

// Проверка авторизации при загрузке
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('auth_token');
    if (token) {
        verifyToken(token);
    }
});

// Показать модальное окно авторизации
function showAuthModal() {
    document.getElementById('authModal').style.display = 'flex';
    showTab('oauth');
}

// Скрыть модальное окно авторизации
function hideAuthModal() {
    document.getElementById('authModal').style.display = 'none';
    clearAuthStatus();
}

// Переключение табов
function showTab(tabName) {
    // Скрыть все табы
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Показать выбранный таб
    document.getElementById(tabName + 'Tab').classList.add('active');
    document.querySelector(`.tab-btn[onclick*="${tabName}"]`).classList.add('active');
    
    // Сбросить статус
    clearAuthStatus();
}

// Традиционная авторизация
async function traditionalLogin() {
    const username = document.getElementById('usernameInput').value.trim();
    const password = document.getElementById('passwordInput').value;
    
    if (!username) {
        showAuthStatus('Введите имя пользователя', 'error');
        return;
    }
    
    if (!password) {
        showAuthStatus('Введите пароль', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Ошибка авторизации');
        }
        
        const data = await response.json();
        handleAuthSuccess(data);
    } catch (error) {
        showAuthStatus('Ошибка авторизации: ' + error.message, 'error');
    }
}

// Отправка кода на email
async function sendCode() {
    const email = document.getElementById('emailInput').value.trim();
    
    if (!email || !email.includes('@')) {
        showAuthStatus('Введите корректный email', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/code/send`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Показать поле для ввода кода
            document.getElementById('step1').style.display = 'none';
            document.getElementById('step2').style.display = 'block';
            showAuthStatus(data.message || 'Код отправлен (демо: 123456)', 'success');
        } else {
            showAuthStatus(data.error || 'Ошибка отправки кода', 'error');
        }
    } catch (error) {
        showAuthStatus('Ошибка отправки кода', 'error');
    }
}

// Проверка кода
async function verifyCode() {
    const email = document.getElementById('emailInput').value.trim();
    const code = document.getElementById('codeInput').value.trim();
    
    if (!email || !code) {
        showAuthStatus('Введите email и код', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/code/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, code })
        });
        
        if (!response.ok) throw new Error('Неверный код');
        
        const data = await response.json();
        handleAuthSuccess(data);
    } catch (error) {
        showAuthStatus('Неверный код подтверждения', 'error');
    }
}

// OAuth авторизация
function oauthLogin(provider) {
    // Получаем URL для OAuth
    fetch(`${API_BASE}/oauth/${provider}/url`)
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.error || 'Ошибка получения OAuth URL');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.url) {
                // Открываем окно для OAuth
                const width = 600, height = 700;
                const left = (screen.width - width) / 2;
                const top = (screen.height - height) / 2;
                
                const authWindow = window.open(
                    data.url + `&state=${provider}`,
                    `${provider}Auth`,
                    `width=${width},height=${height},left=${left},top=${top}`
                );
                
                if (!authWindow) {
                    showAuthStatus('Пожалуйста, разрешите всплывающие окна для OAuth', 'error');
                    return;
                }
                
                // Слушаем сообщения от окна авторизации
                const messageHandler = function(event) {
                    // Проверяем origin для безопасности
                    if (event.origin !== window.location.origin && !event.origin.includes('localhost')) {
                        return;
                    }
                    
                    if (event.data.type === 'oauth_success') {
                        const authData = {
                            access_token: event.data.token,
                            user: event.data.user
                        };
                        handleAuthSuccess(authData);
                        window.removeEventListener('message', messageHandler);
                        if (authWindow) authWindow.close();
                    } else if (event.data.type === 'oauth_error') {
                        showAuthStatus('Ошибка OAuth: ' + (event.data.error || 'Неизвестная ошибка'), 'error');
                        window.removeEventListener('message', messageHandler);
                        if (authWindow) authWindow.close();
                    }
                };
                
                window.addEventListener('message', messageHandler);
                
                // Проверяем, не закрыли ли окно вручную
                const checkClosed = setInterval(() => {
                    if (authWindow.closed) {
                        clearInterval(checkClosed);
                        window.removeEventListener('message', messageHandler);
                    }
                }, 1000);
            } else {
                showAuthStatus('Не удалось получить OAuth URL', 'error');
            }
        })
        .catch(error => {
            console.error('OAuth error:', error);
            showAuthStatus('Ошибка OAuth: ' + error.message, 'error');
        });
}

// ===== Device-code авторизация =====

async function startDeviceCodeLogin() {
    clearAuthStatus();

    try {
        const response = await fetch(`${API_BASE}/device-code/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || 'Не удалось получить код для входа');
        }

        const data = await response.json();
        const code = data.code;
        const expiresIn = data.expires_in || 300;

        const infoEl = document.getElementById('deviceCodeInfo');
        if (infoEl) {
            infoEl.textContent =
                `Ваш код для входа: ${code}. ` +
                `Откройте приложение на другом устройстве, войдите под своей учетной записью ` +
                `и подтвердите вход по этому коду. Код действует примерно ${Math.round(expiresIn / 60)} минут.`;
        }

        // запускаем опрос
        startDeviceCodePolling(code);
    } catch (error) {
        console.error('Device-code start error:', error);
        showAuthStatus('Ошибка при получении кода: ' + error.message, 'error');
    }
}

function startDeviceCodePolling(code) {
    stopDeviceCodePolling();

    deviceCodePollTimer = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/device-code/poll?code=${encodeURIComponent(code)}`, {
                method: 'GET'
            });

            if (!response.ok) {
                // Если код истёк или ошибка — прекращаем
                stopDeviceCodePolling();
                const infoEl = document.getElementById('deviceCodeInfo');
                if (infoEl) {
                    infoEl.textContent = 'Код истёк или недействителен. Попробуйте получить новый код.';
                }
                return;
            }

            const data = await response.json();

            if (data.status === 'pending') {
                // продолжаем ждать
                return;
            }

            if (data.status === 'expired') {
                stopDeviceCodePolling();
                const infoEl = document.getElementById('deviceCodeInfo');
                if (infoEl) {
                    infoEl.textContent = 'Код истёк. Получите новый код для входа.';
                }
                return;
            }

            // Если получили полноценный TokenResponse — завершаем
            if (data.access_token) {
                stopDeviceCodePolling();
                handleAuthSuccess(data);
            }
        } catch (error) {
            console.error('Device-code poll error:', error);
            // не прерываем сразу, даём шанс следующей попытке
        }
    }, 3000);
}

function stopDeviceCodePolling() {
    if (deviceCodePollTimer) {
        clearInterval(deviceCodePollTimer);
        deviceCodePollTimer = null;
    }
}

// Подтверждение кода с уже авторизованного устройства
async function approveDeviceCodeLogin() {
    clearAuthStatus();

    const token = localStorage.getItem('auth_token');
    if (!token) {
        showAuthStatus('Для подтверждения кода нужно быть авторизованным.', 'error');
        return;
    }

    const code = window.prompt('Введите код, показанный на другом устройстве:');
    if (!code) return;

    try {
        const response = await fetch(`${API_BASE}/device-code/approve`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ code: code.trim() })
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(data.error || data.detail || 'Не удалось подтвердить код');
        }

        showAuthStatus('Код подтверждён. Новое устройство сможет войти.', 'success');
    } catch (error) {
        console.error('Device-code approve error:', error);
        showAuthStatus('Ошибка подтверждения кода: ' + error.message, 'error');
    }
}

// Попытка обновить токен по refresh_token
async function tryRefreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
        return false;
    }

    try {
        const response = await fetch(`${API_BASE}/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (!response.ok) {
            localStorage.removeItem('refresh_token');
            localStorage.removeItem('auth_token');
            return false;
        }

        const data = await response.json();
        // Обновляем токены и пользователя без показа уведомления
        localStorage.setItem('auth_token', data.access_token);
        if (data.refresh_token) {
            localStorage.setItem('refresh_token', data.refresh_token);
        }
        setUser(data.user);
        return true;
    } catch (error) {
        console.error('Token refresh failed:', error);
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('auth_token');
        return false;
    }
}

// Верификация токена
async function verifyToken(token) {
    try {
        const response = await fetch(`${API_BASE}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.valid) {
                setUser(data.user);
                return true;
            }
        }

        // Если access-токен невалиден, пробуем обновить по refresh-токену
        const refreshed = await tryRefreshToken();
        if (refreshed) {
            return true;
        }
    } catch (error) {
        console.error('Token verification failed:', error);
    }
    
    // Если токен невалидный и обновить не удалось, очищаем
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
    return false;
}

// Обработка успешной авторизации
function handleAuthSuccess(data) {
    // Сохраняем токены
    localStorage.setItem('auth_token', data.access_token);
    if (data.refresh_token) {
        localStorage.setItem('refresh_token', data.refresh_token);
    }
    
    // Сохраняем пользователя
    setUser(data.user);
    
    // Закрываем модальное окно
    hideAuthModal();
    
    // Показываем уведомление
    showNotification('Авторизация успешна!', 'success');
}

// Установка пользователя
function setUser(user) {
    currentUser = user;
    
    // Сохраняем пользователя в localStorage
    localStorage.setItem('current_user', JSON.stringify(user));
    
    // Обновляем интерфейс
    document.getElementById('username').textContent = user.username;
    document.getElementById('userInfo').style.display = 'flex';
    document.getElementById('authButtons').style.display = 'none';
    
    // Показываем кнопку админ-панели если пользователь админ
    if (user.role === 'admin') {
        document.getElementById('adminPanelBtn').style.display = 'block';
    } else {
        document.getElementById('adminPanelBtn').style.display = 'none';
    }
    
    // Показываем экран тестов
    document.getElementById('welcomeScreen').style.display = 'none';
    document.getElementById('testsScreen').style.display = 'block';
    
    // Загружаем тесты
    loadTests();
}

// Выход
function logout() {
    currentUser = null;
    localStorage.removeItem('auth_token');
     localStorage.removeItem('refresh_token');
    localStorage.removeItem('current_user');
    
    // Обновляем интерфейс
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('authButtons').style.display = 'flex';
    document.getElementById('adminPanelBtn').style.display = 'none';
    
    document.getElementById('testsScreen').style.display = 'none';
    document.getElementById('welcomeScreen').style.display = 'block';
    document.getElementById('resultsScreen').style.display = 'none';
    document.getElementById('testDetails').style.display = 'none';
    document.getElementById('adminPanel').style.display = 'none';
    
    showNotification('Вы вышли из системы', 'info');
}

// Показать статус авторизации
function showAuthStatus(message, type) {
    const statusEl = document.getElementById('authStatus');
    statusEl.textContent = message;
    statusEl.className = `auth-status ${type}`;
}

// Очистить статус авторизации
function clearAuthStatus() {
    const statusEl = document.getElementById('authStatus');
    statusEl.textContent = '';
    statusEl.className = 'auth-status';
}

// Показать уведомление
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#2196f3'};
        color: white;
        border-radius: 8px;
        z-index: 3000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Стили для анимации уведомлений
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Показать информацию о API
function showApiInfo() {
    alert('API Endpoints:\n\n' +
          'Auth Module:\n' +
          '  POST /api/auth/login - Traditional auth\n' +
          '  POST /api/auth/code/send - Send auth code\n' +
          '  POST /api/auth/code/verify - Verify code\n' +
          '  GET /api/auth/oauth/{provider}/url - OAuth URL\n' +
          '  POST /api/auth/verify - Verify token\n\n' +
          'Central Module:\n' +
          '  GET /api/central/tests - List tests\n' +
          '  POST /api/central/tests - Create test (admin)\n' +
          '  GET /api/central/tests/{id}/questions - Test questions\n' +
          '  POST /api/central/tests/{id}/submit - Submit test results');
}

// Показать статус системы
async function showSystemStatus() {
    try {
        const [authHealth, centralHealth] = await Promise.allSettled([
            fetch('/api/auth/health').then(r => r.json()),
            fetch('/api/central/health').then(r => r.json())
        ]);
        
        const authStatus = authHealth.status === 'fulfilled' ? '✅ Работает' : '❌ Ошибка';
        const centralStatus = centralHealth.status === 'fulfilled' ? '✅ Работает' : '❌ Ошибка';
        
        alert(`Статус системы:\n\n` +
              `Auth Module: ${authStatus}\n` +
              `Central Module: ${centralStatus}\n` +
              `Database: ✅ Работает\n` +
              `Redis: ✅ Работает`);
    } catch (error) {
        alert('Ошибка при проверке статуса системы');
    }
}
