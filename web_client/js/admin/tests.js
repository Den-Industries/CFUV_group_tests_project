//функции для взаимодействия с тестами


//функция отображения формы теста
function showTestForm(testId = null) {

  const formContainer = document.getElementById('testFormContainer');
  if (!formContainer) return;

  const formTitle = document.getElementById('testFormTitle');

  if (testId) {
    if (formTitle) formTitle.innerHTML = '<i class="fas fa-edit"></i> Редактирование теста';

    //загружаем данные теста
    editTest(testId);

  } else {

    if (formTitle) formTitle.innerHTML = '<i class="fas fa-plus-circle"></i> Создание нового теста';

    //очищаем форму
    const titleInput = document.getElementById('testTitle');
    const descInput = document.getElementById('testDescription');
    const activeInput = document.getElementById('testActive');
    if (titleInput) titleInput.value = '';
    if (descInput) descInput.value = '';
    if (activeInput) activeInput.checked = true;
    currentTestId = null;
  }

	//плавно прокручиваем страницу к форме
  formContainer.style.display = 'block';
  formContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

//функция скрытия формы (+ сброс текущего теста)
function hideTestForm() {
  const formContainer = document.getElementById('testFormContainer');
  if (formContainer) {
    formContainer.style.display = 'none';
  }
  currentTestId = null;
}

//НОВАЯ функция создания\обновления теста
async function saveTest() {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

	//получаем данные теста
  const titleInput = document.getElementById('testTitle');
  const descInput = document.getElementById('testDescription');
  const activeInput = document.getElementById('testActive');

  if (!titleInput) {
    showNotification('Форма не найдена', 'error');
    return;
  }

	//получаем данные из формы
  const title = titleInput.value.trim();
  const description = descInput ? descInput.value.trim() : '';
  const isActive = activeInput ? activeInput.checked : true;

  if (!title) {
    showNotification('Введите название теста', 'error');
    return;
  }

  try {
    let response;

		//проверяем, редактируем ли существующий тест
    if (currentTestId) {

			//PUT-запрос для обновления существующего теста
      response = await fetch(`/api/central/tests/${currentTestId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          title: title,
          description: description,
          is_active: isActive
        })
      });
    } else {

			//POST-запрос для создания нового теста
      response = await fetch('/api/central/tests', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          title: title,
          description: description,
          is_active: isActive
        })
      });
    }

    if (!response.ok) {
      if (response.status === 403) {
        showNotification('Требуются права администратора', 'error');
        return;
      }
      throw new Error('Ошибка сохранения теста');
    }

    await response.json();
    showNotification(`Тест ${currentTestId ? 'обновлен' : 'создан'} успешно!`, 'success');

    //скрываем форму и обновляем список
    hideTestForm();
    loadAllTests();

    if (typeof loadTestsForQuestionEdit === 'function') {
      loadTestsForQuestionEdit();
    }

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//СТАРАЯ функция создания нового теста (под новую код еще не адаптирован)
async function createNewTest() {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

	//получаем данные из формы
  const title = document.getElementById('testTitle').value.trim();
  const description = document.getElementById('testDescription').value.trim();
  const isActive = document.getElementById('testActive').checked;

  if (!title) {
    showNotification('Введите название теста', 'error');
    return;
  }

  try {
		//POST-запрос для создания нового теста
    const response = await fetch('/api/central/tests', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title: title,
        description: description,
        is_active: isActive
      })
    });

    if (!response.ok) {
      if (response.status === 403) {
        showNotification('Требуются права администратора', 'error');
        return;
      }
      throw new Error('Ошибка создания теста');
    }

    const test = await response.json();
    currentTestId = test.id;

    showNotification('Тест успешно создан! Теперь добавьте вопросы.', 'success');

    //вызов секции вопросов
    const questionsSection = document.getElementById('questionsSection');
    const questionsList = document.getElementById('questionsList');
    if (questionsSection) questionsSection.style.display = 'block';
    if (questionsList) {
      questionsList.innerHTML = `
        <div class="info-message">
          <i class="fas fa-info-circle"></i>
          <p>Вопросы для теста "${title}"</p>
          <p>ID теста: ${test.id}</p>
        </div>
      `;
    }

		//очищаем форму
    document.getElementById('testTitle').value = '';
    document.getElementById('testDescription').value = '';

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//функция загрузки всех тестов
async function loadAllTests() {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  const testsList = document.getElementById('allTestsList');
  if (!testsList) return;

	//экран загрузки
  testsList.innerHTML = `
    <div class="loading">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Загрузка тестов...</p>
    </div>
  `;

  try {

		//GET-запрос к эндпоинту /tests/all
    const response = await fetch('/api/central/tests/all', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      if (response.status === 403) {
        showNotification('Требуются права администратора', 'error');
        return;
      }
      throw new Error('Ошибка загрузки тестов');
    }

    const tests = await response.json();
    displayAllTests(tests);

  } catch (error) {
    testsList.innerHTML = `
      <div class="error">
        <i class="fas fa-exclamation-triangle"></i>
        <p>${error.message}</p>
      </div>
    `;
  }
}

//функция отображения всех тестов
function displayAllTests(tests) {
  const testsList = document.getElementById('allTestsList');
  if (!testsList) return;

	//проверка массива тестов
  if (!tests || tests.length === 0) {
    testsList.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-clipboard-list"></i>
        <h3>Нет тестов</h3>
        <p>Создайте первый тест</p>
      </div>
    `;
    return;
  }

	//создаем карточку теста для админа
  testsList.innerHTML = tests.map(test => `
    <div class="test-admin-card">

      <div class="test-admin-header">

        <h4>${test.title}</h4>
        <span class="test-status ${test.is_active ? 'active' : 'inactive'}">
          ${test.is_active ? 'Активен' : 'Неактивен'}
        </span>

      </div>
            
			<p>${test.description || 'Описание отсутствует'}</p>
            
			<div class="test-meta">

        <span><i class="far fa-user"></i> ID: ${test.id}</span>
        <span><i class="far fa-calendar"></i> ${new Date(test.created_at).toLocaleDateString('ru-RU')}</span>
        <span><i class="fas fa-user-tie"></i> Создатель: ${test.created_by}</span>
			
      </div>

      <div class="test-admin-actions">

        <button class="btn btn-primary" onclick="editTest(${test.id})">
          <i class="fas fa-edit"></i> Редактировать
        </button>

        <button class="btn btn-secondary" onclick="toggleTestStatus(${test.id}, ${!test.is_active})">
          <i class="fas fa-toggle-${test.is_active ? 'off' : 'on'}"></i>
          ${test.is_active ? 'Деактивировать' : 'Активировать'}
        </button>

        <button class="btn btn-danger" onclick="deleteTest(${test.id})">
          <i class="fas fa-trash"></i> Удалить
        </button>

      </div>

    </div>

  `).join('');
}

//функция изменения статуса теста
async function toggleTestStatus(testId, newStatus) {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {

		//сначала загружаем текущие данные теста (чтобы сохранить остальные поля)
    const testResponse = await fetch(`/api/central/tests/${testId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!testResponse.ok) throw new Error('Ошибка загрузки теста');
    const test = await testResponse.json();

		//PUT-запрос для обновления только статуса теста, сохраняя остальные поля
    const response = await fetch(`/api/central/tests/${testId}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title: test.title,
        description: test.description,
        is_active: newStatus
      })
    });

    if (!response.ok) throw new Error('Ошибка обновления теста');

    showNotification(`Тест ${newStatus ? 'активирован' : 'деактивирован'}`, 'success');
    loadAllTests();

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//функция удаления теста
async function deleteTest(testId) {
  if (!confirm('Вы уверены, что хотите удалить этот тест? Это действие нельзя отменить.')) {
    return;
  }

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {

		//DELETE-запрос для удаления теста
    const response = await fetch(`/api/central/tests/${testId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) throw new Error('Ошибка удаления теста');

    showNotification('Тест успешно удален', 'success');
    loadAllTests();

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

// функция редактирования теста
async function editTest(testId) {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {

		//GET-запрос за данными конкретного теста
    const response = await fetch(`/api/central/tests/${testId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) throw new Error('Ошибка загрузки теста');

    const test = await response.json();

    //получаем данные из формы редактирования
    document.getElementById('testTitle').value = test.title || '';
    document.getElementById('testDescription').value = test.description || '';
    document.getElementById('testActive').checked = test.is_active !== false;
    currentTestId = testId;

    //показываем форму редактирования с плавной прокруткой
    const formContainer = document.getElementById('testFormContainer');
    const formTitle = document.getElementById('testFormTitle');
    if (formTitle) formTitle.innerHTML = '<i class="fas fa-edit"></i> Редактирование теста';

    if (formContainer) {
      formContainer.style.display = 'block';
      formContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    showNotification('Тест загружен для редактирования', 'success');

  } catch (error) {
    howNotification(error.message, 'error');
  }
}