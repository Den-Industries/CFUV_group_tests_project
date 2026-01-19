//функции для взаимодействия с вопросами


//функция вызова формы добавления вопроса (для текущего теста)
function addQuestionForm() {

  if (!currentTestId) {
    showNotification('Сначала создайте или выберите тест', 'error');
    return;
  }

  currentEditingQuestionId = null;

  //сбрасываем форму
  const questionText = document.getElementById('questionText');
  const questionType = document.getElementById('questionType');
  const questionPoints = document.getElementById('questionPoints');
  const answersList = document.getElementById('answersList');

  if (questionText) questionText.value = '';
  if (questionType) questionType.value = 'single_choice';
  if (questionPoints) questionPoints.value = '1';
  if (answersList) answersList.innerHTML = '';

  //добавляем 2 пустых ответа по умолчанию
  addAnswerField();
  addAnswerField();

  //вызов модального окна
  const modal = document.getElementById('questionModal');
  if (modal) {
    modal.style.display = 'flex';
  }
}

//функция скрытия модального окна вопроса
function hideQuestionModal() {

  const modal = document.getElementById('questionModal');
  if (modal) {
    modal.style.display = 'none';
  }
  //очищаем форму
  const questionTextEl = document.getElementById('questionText');
  const questionPointsEl = document.getElementById('questionPoints');
  const answersListEl = document.getElementById('answersList');

  if (questionTextEl) questionTextEl.value = '';
  if (questionPointsEl) questionPointsEl.value = '1';
  if (answersListEl) answersListEl.innerHTML = '';

  currentEditingQuestionId = null;
  answerCounter = 0;
}

//функция добавления поля ответа
function addAnswerField() {

  const answersList = document.getElementById('answersList');
  if (!answersList) return;

  answerCounter++;
  const answerId = `answer_${Date.now()}_${answerCounter}`;

	//html для одного поля ответа
  const answerHtml = `
    <div class="answer-item" id="${answerId}">

      <input type="radio" name="correct_answer" class="answer-correct" id="correct_${answerId}">
      <input type="text" id="text_${answerId}" class="answer-text" placeholder="Текст ответа">

      <button type="button" class="remove-btn" onclick="removeAnswerField('${answerId}')">
        <i class="fas fa-times"></i>
      </button>

    </div>
  `;

  answersList.insertAdjacentHTML('beforeend', answerHtml);
}

//функция удаления поля ответа
function removeAnswerField(answerId) {
  const answerElement = document.getElementById(`${answerId}`);
  if (answerElement) {
    answerElement.remove();
  }
}

//функция сохранения вопроса при создании\обновлении
async function saveQuestion() {

  const questionTextEl = document.getElementById('questionText');
  const questionPointsEl = document.getElementById('questionPoints');

  if (!questionTextEl || !questionPointsEl) {
    showNotification('Форма не найдена', 'error');
    return;
  }

	//получаем значения из формы
  const questionText = questionTextEl.value.trim();
  const questionType = 'single_choice'; //всегда single_choice
  const questionPoints = parseInt(questionPointsEl.value) || 1;

  if (!questionText) {
    showNotification('Введите текст вопроса', 'error');
    return;
  }

  if (!currentTestId) {
    showNotification('Сначала создайте тест', 'error');
    return;
  }

  //собираем ответы
  const answerElements = document.querySelectorAll('.answer-item');
  const answers = [];

	//флаг для проверки наличия правильного ответа
  let hasCorrectAnswer = false;

	//собирает ответы из формы
  answerElements.forEach(element => {
    const answerId = element.id;
    const textInput = document.getElementById(`text_${answerId}`);
    const correctInput = document.getElementById(`correct_${answerId}`);

		//если текст не пустой — добавляет в массив
    if (textInput && textInput.value.trim()) {
      const isCorrect = correctInput && correctInput.checked;
      if (isCorrect) hasCorrectAnswer = true;

			//если отмечен как правильный — устанавливает флаг
      answers.push({
        answer_text: textInput.value.trim(),
        is_correct: isCorrect
      });
    }
  });

  if (answers.length === 0) {
    showNotification('Добавьте хотя бы один ответ', 'error');
    return;
  }

  if (!hasCorrectAnswer) {
    showNotification('Выберите хотя бы один правильный ответ', 'error');
    return;
  }

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {
    let response;
    if (currentEditingQuestionId) {

      // Обновление существующего вопроса
			//PUT — если редактируем существующий вопрос (currentEditingQuestionId есть)
      response = await fetch(`/api/central/tests/${currentTestId}/questions/${currentEditingQuestionId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          question_text: questionText,
          question_type: questionType,
          points: questionPoints,
          answers: answers
        })
      });

    } else {
			//POST — если создаем новый вопрос
      // Создание нового вопроса
      response = await fetch(`/api/central/tests/${currentTestId}/questions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          question_text: questionText,
          question_type: questionType,
          points: questionPoints,
          answers: answers
        })
      });
    }

    if (!response.ok) {
      if (response.status === 403) {
        showNotification('Требуются права администратора', 'error');
        return;
      }
      throw new Error('Ошибка сохранения вопроса');
    }

    const result = await response.json();

    if (currentEditingQuestionId) {
      showNotification('Вопрос успешно обновлен', 'success');
    } else {
      showNotification('Вопрос успешно добавлен', 'success');
    }

		//Скрывает модальное окно и сбрасывает ID редактируемого вопроса.
    hideQuestionModal();
    currentEditingQuestionId = null;

    // Обновить список вопросов (edit tab)
    if (document.getElementById('testQuestionsEditList')) {
      loadTestQuestionsForEdit();
    } else {
      //добавляет вопрос в глобальный массив questions (из state.js)
      questions.push({
        id: result.question_id,
        question_text: questionText,
        question_type: questionType,
        points: questionPoints,
        answers: answers
      });
    }

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//функция вызова вкладки редактирования вопросов
async function loadTestsForQuestionEdit() {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  const select = document.getElementById('selectTestForQuestions');
  if (!select) return;

  try {

		//загружаем все тесты и очищаем select
    const response = await fetch('/api/central/tests/all', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error('Ошибка загрузки тестов');
    }

    const tests = await response.json();
    select.innerHTML = '<option value="">-- Выберите тест --</option>';

		//заполняет select опциями
    if (tests && Array.isArray(tests)) {
      tests.forEach(test => {
        const option = document.createElement('option');
        option.value = test.id;
        option.textContent = `${test.title} (ID: ${test.id})`;
        select.appendChild(option);
      });
    }

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//функция для загрузки вопросов выбранного теста
async function loadTestQuestionsForEdit() {

  const select = document.getElementById('selectTestForQuestions');
  if (!select) return;

  const testId = parseInt(select.value);

  if (!testId) {
    const questionsList = document.getElementById('testQuestionsEditList');
    if (questionsList) questionsList.innerHTML = '';
    selectedTestForQuestions = null;
    return;
  }

  selectedTestForQuestions = testId;

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  const questionsList = document.getElementById('testQuestionsEditList');
  if (!questionsList) return;

	//экран загрузки
  questionsList.innerHTML = `
    <div class="loading">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Загрузка вопросов...</p>
    </div>
  `;

  try {

		//загружает вопросы теста (полная версия с правильными ответами, не публичная)
    const response = await fetch(`/api/central/tests/${testId}/questions`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error('Ошибка загрузки вопросов');
    }

    const q = await response.json();
    displayQuestionsForEdit(q, testId);

  } catch (error) {
    questionsList.innerHTML = `
      <div class="error">
        <i class="fas fa-exclamation-triangle"></i>
        <p>${error.message}</p>
      </div>
    `;
  }
}

//функция для отображения вопросов в режиме редактирования
function displayQuestionsForEdit(questions, testId) {

  const questionsList = document.getElementById('testQuestionsEditList');
  if (!questionsList) return;

	//проверка массива вопросов
  if (!questions || questions.length === 0) {
    questionsList.innerHTML = `
      <div class="empty-state">

        <i class="fas fa-question-circle"></i>
        <h3>Нет вопросов</h3>
        <p>Добавьте первый вопрос к этому тесту</p>

        <button class="btn btn-primary" onclick="addQuestionFormForTest(${testId})">
          <i class="fas fa-plus"></i> Добавить вопрос
        </button>

      </div>
    `;
    return;
  }

	//заголовок раздела с количеством вопросов и кнопкой добавления
  questionsList.innerHTML = `
    <div class="questions-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding: 15px; background: #f5f5f5; border-radius: 8px;">

      <h4 style="margin: 0;"><i class="fas fa-list"></i> Вопросы теста (${questions.length})</h4>

      <button class="btn btn-primary" onclick="addQuestionFormForTest(${testId})">
        <i class="fas fa-plus"></i> Добавить вопрос
      </button>

    </div>

    <div class="questions-grid" style="display: grid; gap: 15px;">
      ${questions.map((question, index) => {

        const questionText = question.question_text || '';

				//обрезаем текст вопроса, если он больше 60 символов
        const shortText = questionText.length > 60 ? questionText.substring(0, 60) + '...' : questionText;
				//для каждого вопроса создаем карточку
        return `
          <div class="question-edit-item" style="border: 1px solid #ddd; border-radius: 8px; padding: 15px; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

            <div class="question-edit-header" style="margin-bottom: 10px;">

              <h5 style="margin: 0 0 10px 0; color: #333; font-size: 16px;">
                <span style="color: #666; font-weight: normal;">Вопрос ${index + 1}:</span> ${shortText}
              </h5>

                <div class="question-edit-meta" style="display: flex; gap: 15px; color: #666; font-size: 14px;">

                  <span><i class="fas fa-tag"></i> Тип: <strong>${question.question_type || 'single_choice'}</strong></span>
                  <span><i class="fas fa-star"></i> Баллы: <strong>${question.points || 1}</strong></span>

                </div>

            </div>

            <div class="question-answers" style="margin: 15px 0; padding: 10px; background: #f9f9f9; border-radius: 4px;">
						
              <strong style="display: block; margin-bottom: 8px; color: #555;">Варианты ответов:</strong>

              <ul style="list-style: none; padding: 0; margin: 0;">
                ${(question.answers || []).map((answer) => `
                  <li style="padding: 8px; margin: 5px 0; background: ${answer.is_correct ? '#d4edda' : '#fff'}; border-left: 3px solid ${answer.is_correct ? '#28a745' : '#ddd'}; border-radius: 4px;">

                    <span style="color: ${answer.is_correct ? '#155724' : '#333'};">${answer.answer_text || ''}</span>
                    ${answer.is_correct ? '<span style="color: #28a745; margin-left: 10px;">✓ (верный)</span>' : ''}
                  </li>
                `).join('')}

              </ul>

            </div>

            <div class="question-edit-actions" style="display: flex; gap: 10px; margin-top: 15px;">

              <button class="btn btn-sm btn-primary" onclick="editExistingQuestion(${testId}, ${question.id})" style="flex: 1;">
                <i class="fas fa-edit"></i> Редактировать
              </button>

              <button class="btn btn-sm btn-danger" onclick="deleteQuestionFromTest(${testId}, ${question.id})" style="flex: 1;">
                <i class="fas fa-trash"></i> Удалить
              </button>

            </div>

          </div>
        `;
      }).join('')}

    </div>
  `;
}

//обертка для вызова addQuestionForm() с установкой айди теста
function addQuestionFormForTest(testId) {
  currentTestId = testId;
  if (typeof addQuestionForm === 'function') {
    addQuestionForm();
  }
}

//обертка для editExistingQuestion()
function editQuestionForTest(testId, questionId) {
  editExistingQuestion(testId, questionId);
}

//функция для редактирования существующего вопроса
async function editExistingQuestion(testId, questionId) {
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {

    //загружаем вопросы теста
    const response = await fetch(`/api/central/tests/${testId}/questions`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error('Ошибка загрузки вопросов');
    }

    const questions = await response.json();
    const question = questions.find(q => q.id === questionId);

    if (!question) {
      showNotification('Вопрос не найден', 'error');
      return;
    }

    currentTestId = testId;
    currentEditingQuestionId = questionId;

    //заполняем форму
    const questionTextEl = document.getElementById('questionText');
    const questionTypeEl = document.getElementById('questionType');
    const questionPointsEl = document.getElementById('questionPoints');
    const answersListEl = document.getElementById('answersList');

    if (questionTextEl) questionTextEl.value = question.question_text || '';
    if (questionTypeEl) questionTypeEl.value = question.question_type || 'single_choice';
    if (questionPointsEl) questionPointsEl.value = question.points || 1;
    if (answersListEl) answersListEl.innerHTML = '';

    //заполняем ответы
    if (answersListEl) {
      answersListEl.innerHTML = '';
    }
    answerCounter = 0;

    if (question.answers && question.answers.length > 0) {

      //сортируем ответы по order_index
      const sortedAnswers = [...question.answers].sort((a, b) => (a.order_index || 0) - (b.order_index || 0));

			//для каждого ответа создаем поле, заполняем текст и отмечаем правильность
      sortedAnswers.forEach((answer) => {
        addAnswerField();
        const answerElements = document.querySelectorAll('.answer-item');

        if (answerElements.length > 0) {
          const lastAnswer = answerElements[answerElements.length - 1];
          const answerId = lastAnswer.id;
          const textInput = document.getElementById(`text_${answerId}`);
          const correctInput = document.getElementById(`correct_${answerId}`);
          if (textInput) {
            textInput.value = answer.answer_text || '';
          }
          if (correctInput) {
            correctInput.checked = answer.is_correct || false;
          }
        }
      });

    } else {
      addAnswerField();
      addAnswerField();
    }

    //вызываем модальное окно
    const modal = document.getElementById('questionModal');
    if (modal) {
      modal.style.display = 'flex';
    }

  } catch (error) {
    showNotification(error.message, 'error');
  }
}

//функция для удаления вопроса
async function deleteQuestionFromTest(testId, questionId) {
  if (!confirm('Удалить этот вопрос? Это действие нельзя отменить.')) {
    return;
  }

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  try {

		//DELETE-запрос для удаления вопроса
    const response = await fetch(`/api/central/tests/${testId}/questions/${questionId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      if (response.status === 403) {
        showNotification('Требуются права администратора', 'error');
        return;
      }
      throw new Error('Ошибка удаления вопроса');
    }

    showNotification('Вопрос успешно удален', 'success');
    loadTestQuestionsForEdit();

  } catch (error) {
    showNotification(error.message, 'error');
  }
}