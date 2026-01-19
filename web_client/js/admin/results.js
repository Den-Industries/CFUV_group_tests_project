//функции для просмотра результатов тестов


//физический запрос результатов (в зависимости от ответа вставит в html определенный блок отображения результатов)
async function loadTestResults() {

	//проверка авторизации
  const token = localStorage.getItem('auth_token');
  if (!token) {
    showNotification('Требуется авторизация', 'error');
    return;
  }

  const resultsList = document.getElementById('testResultsList');
  if (!resultsList) return;

	//окно ожидания, пока работает fetch
  resultsList.innerHTML = `
    <div class="loading">
      <i class="fas fa-spinner fa-spin"></i>
      <p>Загрузка результатов...</p>
    </div>
  `;

  try {
		//GET-запрос к эндпоинту результатов
    const response = await fetch('/api/central/results', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

		//true если статус ошибки 400-599
    if (!response.ok) {
      throw new Error('Ошибка загрузки результатов');
    }

    const results = await response.json();
    displayTestResults(results);

  } catch (error) {
    resultsList.innerHTML = `
      <div class="error">
        <i class="fas fa-exclamation-triangle"></i>
        <p>${error.message}</p>
      </div>
    `;
  }
}

//функция для отображения самих результатов
function displayTestResults(results) {
  const resultsList = document.getElementById('testResultsList');
  if (!resultsList) return;

	//если результаты отсутствуют или массив пуст
  if (!results || results.length === 0) {
    resultsList.innerHTML = `
      <div class="empty-state" style="text-align: center; padding: 60px 20px; color: #666;">
        <i class="fas fa-chart-bar" style="font-size: 64px; color: #ddd; margin-bottom: 20px;"></i>
        <h3 style="margin: 10px 0;">Нет результатов</h3>
        <p style="margin: 0;">Пользователи еще не проходили тесты</p>
      </div>
    `;
    return;
  }

	//формируем html блок для отображения результатов
  resultsList.innerHTML = `
    <div style="margin-bottom: 20px; padding: 15px; background: #4361ee; border-radius: 12px; color: white;">
      <h3 style="margin: 0; display: flex; align-items: center; gap: 10px;">
        <i class="fas fa-chart-line"></i>
        <span>Всего результатов: ${results.length}</span>
      </h3>
    </div>
    <div style="display: grid; gap: 15px;">
      ${results.map(result => {

        const percentage = result.percentage || (result.max_score > 0 ? Math.round((result.score / result.max_score) * 100) : 0);

        const scoreClass = percentage >= 90 ? 'excellent' : percentage >= 70 ? 'good' : percentage >= 50 ? 'satisfactory' : 'poor';

				//фиксируем время завершения теста, если оно есть
        const completedDate = result.completed_at ? new Date(result.completed_at) : null;

				//определяем цвет в зависимости от процента результата
        const accent = percentage >= 90 ? '#28a745' : percentage >= 70 ? '#17a2b8' : percentage >= 50 ? '#ffc107' : '#dc3545';
        const badge = accent;

        return `
        <div class="result-card-admin" style="background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); border-left: 4px solid ${accent};">

          <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">

            <div style="flex: 1;">

              <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">

                <i class="fas fa-user" style="color: #4361ee;"></i>
                <strong style="font-size: 16px; color: #333;">${result.user_username || 'Неизвестно'}</strong>

              </div>

              <div style="display: flex; align-items: center; gap: 10px; color: #666; font-size: 14px;">

                <i class="fas fa-clipboard-list" style="color: #999;"></i>
                <span>${result.test_title || 'Неизвестный тест'}</span>

              </div>

            </div>

            <div style="text-align: right;">

              <div class="score-badge-large ${scoreClass}" style="display: inline-block; padding: 10px 20px; border-radius: 8px; font-size: 24px; font-weight: bold; color: white; background: ${badge};">
                ${percentage}%

              </div>

            </div>

          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee;">

            <div style="text-align: center;">

              <div style="font-size: 12px; color: #999; margin-bottom: 5px;">Баллы</div>

              <div style="font-size: 18px; font-weight: bold; color: #333;">${result.score || 0} / ${result.max_score || 0}</div>

            </div>

            <div style="text-align: center;">

              <div style="font-size: 12px; color: #999; margin-bottom: 5px;">ID результата</div>

              <div style="font-size: 14px; color: #666;">#${result.id || '—'}</div>

            </div>

            <div style="text-align: center;">

              <div style="font-size: 12px; color: #999; margin-bottom: 5px;">Дата</div>

              <div style="font-size: 14px; color: #666;">${completedDate ? completedDate.toLocaleDateString('ru-RU') : '—'}</div>

            </div>

            <div style="text-align: center;">

              <div style="font-size: 12px; color: #999; margin-bottom: 5px;">Время</div>

              <div style="font-size: 14px; color: #666;">${completedDate ? completedDate.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'}) : '—'}</div>

            </div>

          </div>

        </div>
        `;

      }).join('')}
    </div>
  `;
}