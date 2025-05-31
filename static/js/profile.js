import { modPow } from './math.js';

export function getUserData() {
    console.log('All cookies:', document.cookie);
    // Находим куки userData
    const userDataCookie = document.cookie.split('; ').find(row => row.startsWith('userData='));

    // Проверяем, существует ли кука
    if (!userDataCookie) {
        console.error('Cookie "userData" not found');
        return {};
    }

    try {
        // Декодируем и парсим данные
        const userData = userDataCookie.split('=')[1];
        const user = JSON.parse(decodeURIComponent(userData));

        // Проверяем, что нужные поля существуют
        if (!user || !user.id || !user.login) {
            throw new Error('Invalid user data structure');
        }

        const userIdElement = document.getElementById('userID');
        const userLoginElement = document.getElementById('userLogin');

        if (userIdElement) userIdElement.textContent = user.id;
        if (userLoginElement) userLoginElement.textContent = user.login;

        return user;


    } catch (error) {
        console.error('Error processing user data:', error);
        return {};
        // Здесь можно добавить обработку ошибки (например, редирект или очистку куки)
    }
    // Обновляем DOM только если элементы существуют

}




export async function userToNonce(user) {
    // 1. Преобразуем объект user в строку JSON
    const userString = JSON.stringify(user);

    // 2. Создаем хеш SHA-256 (можно заменить на другой алгоритм)
    const msgBuffer = new TextEncoder().encode(userString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);

    // 3. Преобразуем хеш в hex-строку
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // 4. Конвертируем hex в bigint
    return BigInt('0x' + hashHex);
}