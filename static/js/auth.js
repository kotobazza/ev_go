// Добавляем токен к запросу
function addAuthHeader(headers = {}) {
    const token = localStorage.getItem('token');
    if (token) {
        console.log('Добавляем токен к запросу:', token);
        return {
            ...headers,
            'Authorization': `Bearer ${token}`
        };
    }
    console.log('Токен не найден в localStorage');
    return headers;
}

// Проверяем авторизацию при загрузке защищенных страниц
function checkAuth() {
    const token = localStorage.getItem('token');
    console.log('Проверка авторизации, токен:', token);

    if (!token) {
        console.log('Токен не найден, редирект на страницу входа');
        window.location.href = '/user/signin';
        return;
    }

    // Проверяем валидность токена
    fetch('/user/profile', {
        headers: addAuthHeader()
    })
        .then(response => {
            console.log('Проверка токена, статус:', response.status);
            if (!response.ok) {
                throw new Error('Token validation failed');
            }
        })
        .catch(error => {
            console.error('Ошибка проверки токена:', error);
            localStorage.removeItem('token');
            window.location.href = '/user/signin';
        });

    // Добавляем обработчик для всех ссылок на странице
    document.addEventListener('click', function (e) {
        const link = e.target.closest('a');
        if (link && link.href.startsWith(window.location.origin)) {
            e.preventDefault();
            console.log('Переход по ссылке:', link.href);

            fetch(link.href, {
                headers: addAuthHeader()
            })
                .then(response => {
                    console.log('Ответ на запрос:', response.status);
                    if (response.redirected) {
                        window.location.href = response.url;
                    } else if (!response.ok) {
                        throw new Error('Unauthorized');
                    } else {
                        window.location.href = link.href;
                    }
                })
                .catch(error => {
                    console.error('Ошибка при переходе:', error);
                    if (error.message === 'Unauthorized') {
                        localStorage.removeItem('token');
                        window.location.href = '/user/signin';
                    }
                });
        }
    });

    // Добавляем обработчик для всех форм
    document.addEventListener('submit', function (e) {
        const form = e.target;
        if (form.method.toLowerCase() === 'post') {
            e.preventDefault();
            console.log('Отправка формы:', form.action);

            const headers = addAuthHeader({
                'Content-Type': 'application/json'
            });
            console.log('Заголовки запроса:', headers);

            const formData = form.enctype === 'application/json' ?
                JSON.stringify(Object.fromEntries(new FormData(form))) :
                new FormData(form);
            console.log('Данные формы:', formData);

            fetch(form.action, {
                method: 'POST',
                headers: headers,
                body: formData
            })
                .then(response => {
                    console.log('Ответ на отправку формы:', response.status);
                    if (response.redirected) {
                        window.location.href = response.url;
                    } else if (!response.ok) {
                        throw new Error('Unauthorized');
                    }
                })
                .catch(error => {
                    console.error('Ошибка при отправке формы:', error);
                    if (error.message === 'Unauthorized') {
                        localStorage.removeItem('token');
                        window.location.href = '/user/signin';
                    }
                });
        }
    });
} 