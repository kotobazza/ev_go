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


export function generateVoteVariants(base, options_amount, pailierPublicKey) {
    const voteVariants = [];
    for (let i = 0; i < options_amount; i++) {
        voteVariants.push(modPow(2n, base * BigInt(i), pailierPublicKey.n ** 2n));
    }
    return voteVariants;
}