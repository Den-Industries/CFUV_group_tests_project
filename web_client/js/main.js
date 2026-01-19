//инициализация при загрузке страницы
document.addEventListener('DOMContentLoaded', () => {

  //инициализация модального окна
  const modal = document.getElementById('authModal');

  //закрытие модального окна при клике вне его области
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      hideAuthModal();
    }
  });

  //инициализация поиска
  const searchInput = document.getElementById('searchInput');
  if (searchInput) {
    searchInput.addEventListener('input', debounce(searchTests, 300));
  }

  //проверка системного статуса
  checkSystemStatus();

	//проверка авторизации
  const savedUser = localStorage.getItem('current_user');
  if (savedUser) {
    const user = JSON.parse(savedUser);
    setUser(user);
  }

  //инициализация админ-панели
  initAdminPanel();
});

//функция инициализации админ-панели
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

//функция дебаунса
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

//функция инициализации поиска тестов
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

//Проверяем, отвечают ли бэкенд-сервисы
async function checkSystemStatus() {

	//проверка модуля авторизации
  try {
    const response = await fetch('/api/auth/health');
    if (response.ok) {
      console.log('Auth Module доступен');
    }
  } catch (error) {
    console.warn('Auth Module недоступен');
  }
  
	//проверка главного модуля
  try {
    const response = await fetch('/api/central/health');
    if (response.ok) {
      console.log('Central Module доступен');
    }
  } catch (error) {
    console.warn('Central Module недоступен');
  }
}