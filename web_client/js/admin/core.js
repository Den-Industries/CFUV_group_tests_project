//функционал админ-панели

//показать панель
function showAdminPanel() {
  document.getElementById('testsScreen').style.display = 'none';
  document.getElementById('resultsScreen').style.display = 'none';
  document.getElementById('adminPanel').style.display = 'block';

  //сбрасываем вкладки
  showAdminTab('manageTests');
  loadAllTests();
}

//скрыть панель
function hideAdminPanel() {
  document.getElementById('adminPanel').style.display = 'none';
  document.getElementById('testsScreen').style.display = 'block';
}

//переключение вкладок
function showAdminTab(tabName) {

  //скрыть все вкладки
  document.querySelectorAll('.admin-tab-content').forEach(tab => {
    tab.classList.remove('active');
  });
  document.querySelectorAll('.admin-tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });

  //показать выбранную вкладку
  const tabElement = document.getElementById(tabName + 'Tab');
  if (tabElement) {
    tabElement.classList.add('active');
  }

  const btnElement = document.querySelector(`.admin-tab-btn[onclick*="${tabName}"]`);
  if (btnElement) {
    btnElement.classList.add('active');
  }

  //скрыть форму теста при переключении вкладок
  if (typeof hideTestForm === 'function') {
    hideTestForm();
	}

  //загрузить данные, если нужно
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