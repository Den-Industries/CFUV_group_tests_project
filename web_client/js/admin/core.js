// web_client/js/admin/core.js

// Показать панель админа
function showAdminPanel() {
    document.getElementById('testsScreen').style.display = 'none';
    document.getElementById('resultsScreen').style.display = 'none';
    document.getElementById('adminPanel').style.display = 'block';

    // Сбросить вкладки
    showAdminTab('manageTests');
    loadAllTests();
}

// Скрыть панель админа
function hideAdminPanel() {
    document.getElementById('adminPanel').style.display = 'none';
    document.getElementById('testsScreen').style.display = 'block';
}

// Переключение вкладок админ-панели
function showAdminTab(tabName) {
    // Скрыть все вкладки
    document.querySelectorAll('.admin-tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.admin-tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Показать выбранную вкладку
    const tabElement = document.getElementById(tabName + 'Tab');
    if (tabElement) {
        tabElement.classList.add('active');
    }

    const btnElement = document.querySelector(`.admin-tab-btn[onclick*="${tabName}"]`);
    if (btnElement) {
        btnElement.classList.add('active');
    }

    // Скрыть форму теста при переключении вкладок
    if (typeof hideTestForm === 'function') {
        hideTestForm();
    }

    // Загрузить данные если нужно
    if (tabName === 'manageTests') {
        loadAllTests();
    } else if (tabName === 'editQuestions') {
        if (typeof loadTestsForQuestionEdit === 'function') {
            loadTestsForQuestionEdit();
        }
    } else if (tabName === 'testResults') {
        if (typeof loadTestResults === 'function') {
            loadTestResults();
        }
    } else if (tabName === 'manageUsers') {
        loadUsers();
    }
}

