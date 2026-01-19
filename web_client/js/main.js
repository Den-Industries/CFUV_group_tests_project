// web_client/js/main.js
// Инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {
    // Инициализация модального окна
    const modal = document.getElementById('authModal');
    
    // Закрытие модального окна при клике вне его
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            hideAuthModal();
        }
    });
    
    // Инициализация поиска
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(searchTests, 300));
    }
    
    // Проверка системного статуса
    checkSystemStatus();
// Проверяем сохраненного пользователя
    const savedUser = localStorage.getItem('current_user');
    if (savedUser) {
        const user = JSON.parse(savedUser);
        setUser(user);
    }
    
    // Инициализация админ-панели
    initAdminPanel();
});

// Инициализация админ-панели
function initAdminPanel() {
    const modal = document.getElementById('questionModal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                hideQuestionModal();
            }
        });
    }
}
// Функция для дебаунса
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Поиск тестов
function searchTests() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const testCards = document.querySelectorAll('.test-card');
    
    testCards.forEach(card => {
        const title = card.querySelector('h3').textContent.toLowerCase();
        const description = card.querySelector('p').textContent.toLowerCase();
        
        if (title.includes(searchTerm) || description.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

// Проверка статуса системы
async function checkSystemStatus() {
    try {
        const response = await fetch('/api/auth/health');
        if (response.ok) {
            console.log('✅ Auth Module доступен');
        }
    } catch (error) {
        console.warn('⚠️ Auth Module недоступен');
    }
    
    try {
        const response = await fetch('/api/central/health');
        if (response.ok) {
            console.log('✅ Central Module доступен');
        }
    } catch (error) {
        console.warn('⚠️ Central Module недоступен');
    }
}

// Глобальные функции
window.showAuthModal = showAuthModal;
window.hideAuthModal = hideAuthModal;
window.showTab = showTab;
window.traditionalLogin = traditionalLogin;
window.sendCode = sendCode;
window.verifyCode = verifyCode;
window.oauthLogin = oauthLogin;
window.logout = logout;
window.loadTests = loadTests;
window.showTestDetails = showTestDetails;
window.hideTestDetails = hideTestDetails;
window.selectAnswer = selectAnswer;
window.submitTest = submitTest;
window.goToTests = goToTests;
// retryTest removed - no longer needed
window.showApiInfo = showApiInfo;
window.showSystemStatus = showSystemStatus;
