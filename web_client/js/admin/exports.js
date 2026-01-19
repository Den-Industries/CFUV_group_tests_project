//экспортируем все функции в глобальную область видимости (для inline onclick в HTML)


//основные функции админ-панели
window.showAdminPanel = showAdminPanel;
window.hideAdminPanel = hideAdminPanel;
window.showAdminTab = showAdminTab;

//управление тестами
window.showTestForm = showTestForm;
window.hideTestForm = hideTestForm;
window.saveTest = saveTest;
window.loadAllTests = loadAllTests;
window.loadTests = loadTests;
window.toggleTestStatus = toggleTestStatus;
window.deleteTest = deleteTest;
window.editTest = editTest;
window.showTestDetails = showTestDetails;
window.hideTestDetails = hideTestDetails;
window.selectAnswer = selectAnswer;
window.submitTest = submitTest;


//управление вопросами
window.addQuestionForm = addQuestionForm;
window.hideQuestionModal = hideQuestionModal;
window.addAnswerField = addAnswerField;
window.removeAnswerField = removeAnswerField;
window.saveQuestion = saveQuestion;

//управление пользователями
window.loadUsers = loadUsers;
window.createUser = createUser;
window.editUser = editUser;
window.hideEditUserModal = hideEditUserModal;
window.saveUserChanges = saveUserChanges;
window.resetUserPassword = resetUserPassword;
window.deleteCurrentUser = deleteCurrentUser;
window.confirmDeleteUser = confirmDeleteUser;

//редактирование вопросов
window.loadTestsForQuestionEdit = loadTestsForQuestionEdit;
window.loadTestQuestionsForEdit = loadTestQuestionsForEdit;
window.addQuestionFormForTest = addQuestionFormForTest;
window.editQuestionForTest = editQuestionForTest;
window.editExistingQuestion = editExistingQuestion;
window.deleteQuestionFromTest = deleteQuestionFromTest;

//результаты тестов
window.loadTestResults = loadTestResults;

//авторизация
window.showAuthModal = showAuthModal;
window.hideAuthModal = hideAuthModal;
window.logout = logout;
window.oauthLogin = oauthLogin;
window.traditionalLogin = traditionalLogin;
window.sendCode = sendCode;
window.verifyCode = verifyCode;

//навигация
window.showTab = showTab;
window.goToTests = goToTests;

//утилиты
window.showApiInfo = showApiInfo;
window.showSystemStatus = showSystemStatus;