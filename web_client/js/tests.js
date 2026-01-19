// web_client/js/tests.js
const CENTRAL_API = '/api/central';
let currentTest = null;

// Загрузка тестов
async function loadTests() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }
    
    const testsList = document.getElementById('testsList');
    testsList.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Загрузка тестов...</p>
        </div>
    `;
    
    try {
        const response = await fetch(`${CENTRAL_API}/tests`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                localStorage.removeItem('auth_token');
                location.reload();
                return;
            }
            throw new Error('Ошибка загрузки тестов');
        }
        
        const tests = await response.json();
        displayTests(tests);
    } catch (error) {
        testsList.innerHTML = `
            <div class="error">
                <i class="fas fa-exclamation-triangle"></i>
                <p>${error.message}</p>
                <button class="btn btn-primary" onclick="loadTests()">
                    Повторить попытку
                </button>
            </div>
        `;
    }
}

// Отображение тестов
function displayTests(tests) {
    const testsList = document.getElementById('testsList');
    if (!testsList) {
        console.error('testsList element not found in displayTests');
        return;
    }
    
    if (!tests || tests.length === 0) {
        testsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-clipboard-list"></i>
                <h3>Нет доступных тестов</h3>
                <p>Тесты еще не созданы или находятся на модерации</p>
            </div>
        `;
        return;
    }
    
    // Фильтруем только активные тесты
    const activeTests = tests.filter(test => test.is_active !== false);
    
    if (activeTests.length === 0) {
        testsList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-clipboard-list"></i>
                <h3>Нет доступных тестов</h3>
                <p>Все тесты неактивны</p>
            </div>
        `;
        return;
    }
    
    testsList.innerHTML = activeTests.map(test => `
        <div class="test-card" onclick="showTestDetails(${test.id})">
            <h3>${test.title || 'Без названия'}</h3>
            <p>${test.description || 'Описание отсутствует'}</p>
            <div class="test-meta">
                <span><i class="far fa-user"></i> ID: ${test.id}</span>
                <span><i class="far fa-calendar"></i> ${test.created_at ? new Date(test.created_at).toLocaleDateString('ru-RU') : '—'}</span>
            </div>
            <div class="test-actions">
                <button class="btn btn-primary" onclick="event.stopPropagation(); showTestDetails(${test.id})">
                    <i class="fas fa-play"></i> Начать тест
                </button>
            </div>
        </div>
    `).join('');
}

// Показать детали теста
async function showTestDetails(testId) {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }
    
    // Сбрасываем предыдущий тест
    currentTest = null;
    
    try {
        // Загружаем вопросы теста (публичная версия без правильных ответов)
        const response = await fetch(`${CENTRAL_API}/tests/${testId}/questions/public`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Ошибка загрузки теста');
        }
        
        const questions = await response.json();
        
        if (!questions || questions.length === 0) {
            showNotification('У этого теста нет вопросов', 'warning');
            return;
        }
        
        // Сохраняем текущий тест с правильным ID
        currentTest = {
            id: parseInt(testId),  // Убеждаемся, что ID - число
            questions: questions,
            userAnswers: {}
        };
        
        console.log('Loaded test:', currentTest.id, 'with', questions.length, 'questions');
        
        // Показываем детали теста
        const testsList = document.getElementById('testsList');
        const testDetails = document.getElementById('testDetails');
        
        if (testsList) testsList.style.display = 'none';
        if (testDetails) testDetails.style.display = 'block';
        
        displayTestQuestions(questions);
    } catch (error) {
        console.error('Error loading test:', error);
        showNotification(error.message, 'error');
    }
}

// Отображение вопросов теста
function displayTestQuestions(questions) {
    const testContent = document.getElementById('testContent');
    
    testContent.innerHTML = `
        <h3><i class="fas fa-question-circle"></i> Тестирование</h3>
        <p class="test-info">Вопросов: ${questions.length}</p>
        <div id="questionsContainer"></div>
        <div class="test-controls">
            <button class="btn btn-primary" onclick="submitTest()">
                <i class="fas fa-paper-plane"></i> Отправить ответы
            </button>
        </div>
    `;
    
    const questionsContainer = document.getElementById('questionsContainer');
    
    questions.forEach((question, index) => {
        const questionEl = document.createElement('div');
        questionEl.className = 'question';
        questionEl.innerHTML = `
            <h4>Вопрос ${index + 1}: ${question.question_text}</h4>
            <div class="answers" id="answers_${question.id}">
                <!-- Варианты ответов будут загружены -->
            </div>
        `;
        questionsContainer.appendChild(questionEl);
        
        // Загружаем варианты ответов для этого вопроса из данных вопроса
        loadQuestionAnswers(question.id, question.answers || []);
    });
}

// Загрузка вариантов ответов
function loadQuestionAnswers(questionId, answers) {
    const answersContainer = document.getElementById(`answers_${questionId}`);
    
    if (!answersContainer) {
        console.error(`Answers container not found for question ${questionId}`);
        return;
    }
    
    if (!answers || answers.length === 0) {
        answersContainer.innerHTML = '<p style="color: #999; padding: 10px;">Нет вариантов ответа</p>';
        return;
    }
    
    // Сортируем ответы по order_index (как на бэкенде)
    const sortedAnswers = [...answers].sort((a, b) => {
        const aIndex = a.order_index !== undefined ? a.order_index : (a.id || 0);
        const bIndex = b.order_index !== undefined ? b.order_index : (b.id || 0);
        return aIndex - bIndex;
    });
    
    // Отладочный лог можно включить при необходимости
    // console.log(`Loading answers for question ${questionId}:`, sortedAnswers.map(a => ({text: a.answer_text, order: a.order_index})));

    answersContainer.innerHTML = sortedAnswers.map((answer, index) => `
        <div class="answer-option" onclick="selectAnswer(${questionId}, ${index})" id="answer_${questionId}_${index}">
            <input type="radio" name="question_${questionId}" id="radio_${questionId}_${index}" value="${index}">
            <label for="radio_${questionId}_${index}">${answer.answer_text || ''}</label>
        </div>
    `).join('');
}

// Выбор ответа
function selectAnswer(questionId, answerIndex) {
    // Сохраняем ответ пользователя
    currentTest.userAnswers[questionId] = answerIndex;
    
    // Визуально выделяем выбранный ответ
    const answers = document.querySelectorAll(`#answers_${questionId} .answer-option`);
    answers.forEach((answer, index) => {
        answer.classList.toggle('selected', index === answerIndex);
    });
}

// Скрыть детали теста
function hideTestDetails() {
    document.getElementById('testDetails').style.display = 'none';
    document.getElementById('testsList').style.display = 'grid';
}

// Отправить тест
async function submitTest() {
    const token = localStorage.getItem('auth_token');
    if (!token || !currentTest) {
        showNotification('Ошибка отправки теста', 'error');
        return;
    }
    
    // Подготавливаем данные для отправки
    const answers = Object.entries(currentTest.userAnswers).map(([questionId, answerIndex]) => ({
        question_id: parseInt(questionId),
        answer_index: answerIndex
    }));
    
    if (answers.length === 0) {
        showNotification('Ответьте хотя бы на один вопрос', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${CENTRAL_API}/tests/${currentTest.id}/submit`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                test_id: currentTest.id,
                answers: answers
            })
        });
        
        if (!response.ok) throw new Error('Ошибка отправки теста');
        
        const result = await response.json();
        showResults(result);
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

// Показать результаты
function showResults(result) {
    document.getElementById('testDetails').style.display = 'none';
    document.getElementById('testsScreen').style.display = 'none';
    document.getElementById('resultsScreen').style.display = 'block';
    
    const resultsContent = document.getElementById('resultsContent');
    
    // Используем реальные данные из ответа сервера
    const score = result.score || 0;
    const maxScore = result.max_score || 1;
    const percentage = result.percentage || Math.round((score / maxScore) * 100);
    const completedAt = result.completed_at ? new Date(result.completed_at) : new Date();
    
    let message = '';
    let messageClass = '';
    if (percentage >= 90) {
        message = 'Отличный результат!';
        messageClass = 'excellent';
    } else if (percentage >= 70) {
        message = 'Хороший результат!';
        messageClass = 'good';
    } else if (percentage >= 50) {
        message = 'Удовлетворительный результат';
        messageClass = 'satisfactory';
    } else {
        message = 'Попробуйте еще раз';
        messageClass = 'poor';
    }
    
    resultsContent.innerHTML = `
        <div class="result-card ${messageClass}">
            <div class="result-icon">
                <i class="fas fa-${percentage >= 90 ? 'trophy' : percentage >= 70 ? 'medal' : percentage >= 50 ? 'certificate' : 'redo'}"></i>
            </div>
            <h3>Тест завершен!</h3>
            <div class="result-score">${percentage}%</div>
            <div class="result-score-detail">${score} из ${maxScore} баллов</div>
            <p class="result-message">${message}</p>
        </div>
        
        <div class="result-details">
            <h4><i class="fas fa-chart-pie"></i> Детали результатов:</h4>
            <div class="result-info-grid">
                <div class="result-info-item">
                    <i class="fas fa-clipboard-list"></i>
                    <span>Тест ID: ${currentTest.id}</span>
                </div>
                <div class="result-info-item">
                    <i class="fas fa-clock"></i>
                    <span>Завершено: ${completedAt.toLocaleString('ru-RU')}</span>
                </div>
                <div class="result-info-item">
                    <i class="fas fa-percentage"></i>
                    <span>Процент: ${percentage}%</span>
                </div>
                <div class="result-info-item">
                    <i class="fas fa-star"></i>
                    <span>Баллы: ${score}/${maxScore}</span>
                </div>
            </div>
            
            <div class="result-actions">
                <button class="btn btn-primary" onclick="goToTests()">
                    <i class="fas fa-list"></i> К списку тестов
                </button>
            </div>
        </div>
    `;
}

// Вернуться к списку тестов
function goToTests() {
    // Скрываем все экраны
    const resultsScreen = document.getElementById('resultsScreen');
    const testsScreen = document.getElementById('testsScreen');
    const testDetails = document.getElementById('testDetails');
    const testsList = document.getElementById('testsList');
    
    if (resultsScreen) resultsScreen.style.display = 'none';
    if (testDetails) {
        testDetails.style.display = 'none';
        const testContent = document.getElementById('testContent');
        if (testContent) testContent.innerHTML = '';
    }
    
    // Сбрасываем текущий тест
    currentTest = null;
    
    // Показываем экран тестов
    if (testsScreen) {
        testsScreen.style.display = 'block';
    }
    
    // Убеждаемся, что список тестов виден
    if (testsList) {
        testsList.style.display = 'grid';
    }
    
    // Загружаем тесты заново с небольшой задержкой для надежности
    setTimeout(() => {
        loadTests();
    }, 100);
}

// Повторить тест
function retryTest() {
    document.getElementById('resultsScreen').style.display = 'none';
    showTestDetails(currentTest.id);
}
