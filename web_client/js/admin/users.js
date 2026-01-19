// web_client/js/admin/users.js

// Функции для управления пользователями
async function loadUsers() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }

    const usersList = document.getElementById('usersList');
    if (!usersList) {
        console.error('usersList element not found');
        showNotification('Элемент списка пользователей не найден', 'error');
        return;
    }

    usersList.innerHTML = `
        <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>Загрузка пользователей...</p>
        </div>
    `;

    try {
        const response = await fetch('/api/central/users', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            if (response.status === 403) {
                showNotification('Требуются права администратора', 'error');
                usersList.innerHTML = '<div class="error">Требуются права администратора</div>';
                return;
            }
            const errorText = await response.text();
            throw new Error(`Ошибка загрузки пользователей: ${errorText}`);
        }

        const users = await response.json();

        if (users && Array.isArray(users)) {
            displayUsersTable(users);
        } else {
            console.error('Users is not an array:', users);
            displayUsersTable([]);
        }
    } catch (error) {
        console.error('Error loading users:', error);
        usersList.innerHTML = `
            <div class="error">
                <i class="fas fa-exclamation-triangle"></i>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function displayUsersTable(users) {
    const usersList = document.getElementById('usersList');
    if (!usersList) {
        console.error('usersList element not found in displayUsersTable');
        return;
    }

    if (!users || !Array.isArray(users) || users.length === 0) {
        usersList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-users"></i>
                <h3>Нет пользователей</h3>
                <p>Создайте первого пользователя</p>
            </div>
        `;
        return;
    }

    const currentUser = JSON.parse(localStorage.getItem('current_user') || '{}');

    usersList.innerHTML = `
        <table class="users-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Имя пользователя</th>
                    <th>Email</th>
                    <th>Роль</th>
                    <th>Дата создания</th>
                    <th>Действия</th>
                </tr>
            </thead>
            <tbody>
                ${users.map((user) => {
                    try {
                        const username = String(user.username || '');
                        const email = String(user.email || '—');
                        const role = String(user.role || 'user');
                        const userId = user.id || 0;
                        const currentUsername = currentUser.username || '';
                        const isCurrentUser = username === currentUsername;
                        const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString('ru-RU') : '—';
                        const deleteButton = !isCurrentUser
                            ? `<button class="btn btn-sm btn-warning" onclick="confirmDeleteUser(${userId}, '${username.replace(/'/g, "\\'")}')"><i class="fas fa-trash"></i> Удалить</button>`
                            : '';
                        const editDisabled = isCurrentUser ? 'disabled' : '';

                        return `<tr>
                            <td>${userId}</td>
                            <td><strong>${username}</strong>${isCurrentUser ? '<span class="badge badge-you">Вы</span>' : ''}</td>
                            <td>${email}</td>
                            <td><span class="user-role ${role}">${role === 'admin' ? '👑 Админ' : '👤 Пользователь'}</span></td>
                            <td>${createdDate}</td>
                            <td>
                                <div class="user-actions">
                                    <button class="btn btn-sm btn-primary" onclick="editUser(${userId})" ${editDisabled}><i class="fas fa-edit"></i> Редактировать</button>
                                    ${deleteButton}
                                </div>
                            </td>
                        </tr>`;
                    } catch (e) {
                        console.error('Error rendering user:', user, e);
                        return `<tr><td colspan="6">Ошибка отображения пользователя</td></tr>`;
                    }
                }).join('')}
            </tbody>
        </table>
    `;
}

async function createUser() {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }

    const username = document.getElementById('newUsername').value.trim();
    const email = document.getElementById('newEmail').value.trim();
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newRole').value;

    if (!username || !password) {
        showNotification('Заполните обязательные поля', 'error');
        return;
    }

    if (password.length < 4) {
        showNotification('Пароль должен быть не менее 4 символов', 'error');
        return;
    }

    try {
        showNotification('Создание пользователя...', 'info');

        const response = await fetch('/api/central/users', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                email: email || null,
                password: password,
                role: role
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.detail || 'Ошибка создания пользователя');
        }

        showNotification(`Пользователь "${username}" успешно создан`, 'success');

        // Очищаем форму
        document.getElementById('newUsername').value = '';
        document.getElementById('newEmail').value = '';
        document.getElementById('newPassword').value = '';

        // Обновляем список пользователей
        loadUsers();
    } catch (error) {
        showNotification(`Ошибка: ${error.message}`, 'error');
    }
}

function editUser(userId) {
    currentEditingUserId = userId;

    // Загружаем данные пользователя
    loadUserDetails(userId);

    // Показываем модальное окно
    document.getElementById('editUserModal').style.display = 'flex';
}

async function loadUserDetails(userId) {
    const token = localStorage.getItem('auth_token');
    if (!token) return;

    try {
        const response = await fetch(`/api/central/users/${userId}`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const user = await response.json();
            // Убеждаемся, что значения не undefined
            document.getElementById('editUsername').value = String(user.username || '');
            document.getElementById('editEmail').value = String(user.email || '');
            document.getElementById('editRole').value = String(user.role || 'user');
        } else {
            const errorData = await response.json().catch(() => ({}));
            showNotification(errorData.detail || 'Ошибка загрузки данных пользователя', 'error');
        }
    } catch (error) {
        console.error('Error loading user details:', error);
        showNotification('Ошибка загрузки данных пользователя', 'error');
    }
}

function hideEditUserModal() {
    document.getElementById('editUserModal').style.display = 'none';
    currentEditingUserId = null;

    // Очищаем поля
    document.getElementById('editUsername').value = '';
    document.getElementById('editEmail').value = '';
    document.getElementById('editPassword').value = '';
    document.getElementById('editRole').value = 'user';
}

async function saveUserChanges() {
    if (!currentEditingUserId) return;

    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }

    const username = document.getElementById('editUsername').value.trim();
    const email = document.getElementById('editEmail').value.trim();
    const password = document.getElementById('editPassword').value;
    const role = document.getElementById('editRole').value;

    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (role) updateData.role = role;
    if (password) updateData.password = password;

    try {
        showNotification('Сохранение изменений...', 'info');

        const response = await fetch(`/api/central/users/${currentEditingUserId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(updateData)
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({detail: 'Ошибка обновления пользователя'}));
            throw new Error(error.detail || 'Ошибка обновления пользователя');
        }

        showNotification('Изменения сохранены', 'success');
        hideEditUserModal();
        loadUsers();
    } catch (error) {
        showNotification(`Ошибка: ${error.message}`, 'error');
    }
}

async function resetUserPassword() {
    if (!currentEditingUserId) return;

    if (!confirm('Сбросить пароль пользователя на "password"?')) {
        return;
    }

    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/central/users/${currentEditingUserId}/reset-password`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({detail: 'Ошибка сброса пароля'}));
            throw new Error(error.detail || 'Ошибка сброса пароля');
        }

        showNotification('Пароль сброшен на "password"', 'success');
    } catch (error) {
        showNotification(`Ошибка: ${error.message}`, 'error');
    }
}

function confirmDeleteUser(userId, username) {
    if (confirm(`Вы уверены, что хотите удалить пользователя "${username}"?\nЭто действие нельзя отменить.`)) {
        deleteUser(userId);
    }
}

async function deleteUser(userId) {
    const token = localStorage.getItem('auth_token');
    if (!token) {
        showNotification('Требуется авторизация', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/central/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            throw new Error('Ошибка удаления пользователя');
        }

        showNotification('Пользователь удален', 'success');
        loadUsers();
    } catch (error) {
        showNotification(`Ошибка: ${error.message}`, 'error');
    }
}

function deleteCurrentUser() {
    if (!currentEditingUserId) return;

    if (confirm('Удалить этого пользователя?\nЭто действие нельзя отменить.')) {
        deleteUser(currentEditingUserId);
        hideEditUserModal();
    }
}

