// web_client/js/admin/exports.js
// Экспортируем все функции в глобальную область видимости (для inline onclick в HTML)

window.showAdminPanel = showAdminPanel;
window.hideAdminPanel = hideAdminPanel;
window.showAdminTab = showAdminTab;

window.showTestForm = showTestForm;
window.hideTestForm = hideTestForm;
window.saveTest = saveTest;
window.loadAllTests = loadAllTests;
window.toggleTestStatus = toggleTestStatus;
window.deleteTest = deleteTest;
window.editTest = editTest;

window.addQuestionForm = addQuestionForm;
window.hideQuestionModal = hideQuestionModal;
window.addAnswerField = addAnswerField;
window.removeAnswerField = removeAnswerField;
window.saveQuestion = saveQuestion;

window.loadUsers = loadUsers;
window.createUser = createUser;
window.editUser = editUser;
window.hideEditUserModal = hideEditUserModal;
window.saveUserChanges = saveUserChanges;
window.resetUserPassword = resetUserPassword;
window.deleteCurrentUser = deleteCurrentUser;
window.confirmDeleteUser = confirmDeleteUser;

window.loadTestsForQuestionEdit = loadTestsForQuestionEdit;
window.loadTestQuestionsForEdit = loadTestQuestionsForEdit;
window.addQuestionFormForTest = addQuestionFormForTest;
window.editQuestionForTest = editQuestionForTest;
window.editExistingQuestion = editExistingQuestion;
window.deleteQuestionFromTest = deleteQuestionFromTest;

window.loadTestResults = loadTestResults;

