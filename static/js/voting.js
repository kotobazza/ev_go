

window.initializeZKP = function (params) {


    const { voting_id, options_amount, publicKey, rsaSignPublicKey } = params;


    console.log("rsaSignPublicKey:", rsaSignPublicKey);
    function gcd(a, b) {
        a = BigInt(a);
        b = BigInt(b);

        while (b !== 0n) {
            [a, b] = [b, a % b];
        }

        return a;
    }

    function lcm(a, b) {
        a = BigInt(a);
        b = BigInt(b);

        if (a === 0n || b === 0n) {
            return 0n;
        }

        const absProduct = (a * b) < 0n ? -(a * b) : a * b;
        const gcdValue = gcd(a, b);

        return absProduct / BigInt(gcdValue);
    }

    function L(x, n) {
        return (x - 1n) / n
    }

    function modPow(base, exponent, modulus) {
        if (modulus === 1n) return 0n;
        let result = 1n;
        base = base % modulus;
        while (exponent > 0n) {
            if (exponent % 2n === 1n) {
                result = (result * base) % modulus;
            }
            exponent = exponent >> 1n;
            base = (base * base) % modulus;
        }
        return result;
    }

    function modInverse(a, m) {
        a = BigInt(a);
        m = BigInt(m);

        if (m === 1n) return 0n;

        let [old_r, r] = [a, m];
        let [old_s, s] = [1n, 0n];
        let [old_t, t] = [0n, 1n];

        while (r !== 0n) {
            const quotient = old_r / r;
            [old_r, r] = [r, old_r - quotient * r];
            [old_s, s] = [s, old_s - quotient * s];
            [old_t, t] = [t, old_t - quotient * t];
        }

        if (old_r !== 1n) {
            throw new Error('Обратный элемент не существует: a и m не взаимно просты');
        }

        return (old_s % m + m) % m;
    }

    function randomBigInt(max) {
        const bytesNeeded = Math.ceil(max.toString(2).length / 8);
        let randomValue;

        do {
            const randomBytes = new Uint8Array(bytesNeeded);
            crypto.getRandomValues(randomBytes);
            randomValue = BigInt('0x' + Array.from(randomBytes)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')) % max;
        } while (randomValue === 0n);

        return randomValue;
    }




    // Генерация вариантов голосования
    const voteVariants = [];
    for (let i = 0; i < options_amount; i++) {
        voteVariants.push(modPow(2n, 30n * BigInt(i), publicKey.n ** 2n));
    }

    console.log("vote variants ready");


    async function generateProof(n, validMessages, messageToEncrypt) {
        console.log("=== Generating proof ===");
        const nn = n * n;
        const numOfMessages = validMessages.length;

        // Генерация случайного r и шифрование сообщения
        let r;
        do {
            r = randomBigInt(n);
        } while (gcd(r, n) !== 1n);
        console.log("Generated r:", r.toString());

        const g = n + 1n;  // Стандартное значение g для Paillier
        const ciphertext = (modPow(g, messageToEncrypt, nn) * modPow(r, n, nn)) % nn;
        console.log("Generated ciphertext:", ciphertext.toString());

        // Вычисление u_i для каждого допустимого сообщения
        const uiVec = [];
        for (const m of validMessages) {
            const gm = modPow(g, m, nn);
            const gmInv = modInverse(gm, nn);
            const ui = (ciphertext * gmInv) % nn;
            uiVec.push(ui);
        }

        // Генерация случайных e_j и z_j для всех сообщений, кроме истинного
        const B = 256;  // Параметр безопасности
        const twoToB = 2n ** 256n;

        const eiVec = [];
        const ziVec = [];
        for (let i = 0; i < numOfMessages - 1; i++) {
            eiVec.push(randomBigInt(twoToB));
            ziVec.push(randomBigInt(n));
        }

        // Генерация случайного w
        const w = randomBigInt(n);
        console.log("Generated w:", w.toString());

        // Находим индекс истинного сообщения
        const trueIndex = validMessages.findIndex(m => m === messageToEncrypt);
        console.log("True index:", trueIndex);

        // Вычисляем a_i для каждого сообщения
        const aiVec = [];
        let j = 0;
        for (let i = 0; i < numOfMessages; i++) {
            if (i === trueIndex) {
                const ai = modPow(w, n, nn);
                aiVec.push(ai);
            } else {
                const ziN = modPow(ziVec[j], n, nn);
                const uiEi = modPow(uiVec[i], eiVec[j], nn);
                const uiEiInv = modInverse(uiEi, nn);
                const ai = (ziN * uiEiInv) % nn;
                aiVec.push(ai);
                j++;
            }
        }

        // Вычисляем challenge (chal)
        const hash = await sha256(aiVec);
        const chal = BigInt('0x' + hash) % twoToB;
        console.log("Challenge:", chal.toString());

        // Вычисляем e_i для истинного сообщения
        let eiSum = 0n;
        for (const ei of eiVec) {
            eiSum = (eiSum + ei) % twoToB;
        }
        const ei = (chal - eiSum + twoToB) % twoToB;

        // Вычисляем z_i для истинного сообщения
        const riEi = modPow(r, ei, n);
        const zi = (w * riEi) % n;

        // Собираем полные векторы e_vec и z_vec
        const eVec = [];
        const zVec = [];
        j = 0;
        for (let i = 0; i < numOfMessages; i++) {
            if (i === trueIndex) {
                eVec.push(ei);
                zVec.push(zi);
            } else {
                eVec.push(eiVec[j]);
                zVec.push(ziVec[j]);
                j++;
            }
        }

        return {
            e_vec: eVec,
            z_vec: zVec,
            a_vec: aiVec,
            ciphertext: ciphertext,
            valid_messages: validMessages
        };
    }

    // Вспомогательная функция для вычисления SHA-256
    async function sha256(values) {
        // Преобразуем все значения в строки и конкатенируем их напрямую,
        // в точности как это делается в C++ версии
        console.log("JS hashing values:");
        for (const value of values) {
            console.log(value.toString());
        }
        const encoder = new TextEncoder();
        let fullData = new Uint8Array(0);

        // Последовательно добавляем каждое значение в буфер,
        // имитируя поведение EVP_DigestUpdate
        for (const value of values) {
            const valueStr = value.toString();
            const valueData = encoder.encode(valueStr);

            // Создаем новый буфер с увеличенным размером
            const newFullData = new Uint8Array(fullData.length + valueData.length);
            newFullData.set(fullData);
            newFullData.set(valueData, fullData.length);
            fullData = newFullData;
        }

        // Вычисляем финальный хеш
        const hashBuffer = await crypto.subtle.digest('SHA-256', fullData);

        // Преобразуем в hex-строку
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        console.log("JS hash hex:", hashHex);
        const finalResult = BigInt('0x' + hashHex);
        console.log("JS final result:", finalResult.toString());
        return hashHex;
    }

    function checkBigIntRange(value, modulus) {
        if (value < 0n || value >= modulus) {
            console.log("WARNING: Значение вне допустимого диапазона!");
            console.log("value:", value.toString());
            console.log("modulus:", modulus.toString());
            return false;
        }
        return true;
    }

    async function verify(e_vec, z_vec, a_vec, ciphertext, valid_messages, n) {
        console.log("=== Начало верификации ===");
        const numOfMessages = valid_messages.length;
        const B = 256;
        const twoToB = BigInt(2) ** BigInt(B);
        const nn = n * n;
        const g = n + 1n;

        // Проверка суммы e_i
        console.log("\n=== Проверка суммы e_i ===");
        const hash = await sha256(a_vec);
        const chal = BigInt('0x' + hash) % twoToB;
        console.log("chal:", chal.toString());

        let eiSum = 0n;
        for (const e of e_vec) {
            eiSum = (eiSum + e) % twoToB;
        }
        console.log("eiSum:", eiSum.toString());

        if (chal !== eiSum) {
            console.log("Проверка суммы e_i не пройдена");
            return false;
        }

        // Вычисление u_i для каждого допустимого сообщения
        console.log("\n=== Вычисление u_i ===");
        const uiVec = [];
        for (let i = 0; i < valid_messages.length; i++) {
            const m = valid_messages[i];
            console.log(`\nВычисление u_${i}:`);

            // g^m mod n² (точно как в Python)
            const gm = modPow(g, m, nn);
            console.log("gm:", gm.toString());

            // (g^m)^(-1) mod n²
            const gmInv = modInverse(gm, nn);
            console.log("gmInv:", gmInv.toString());

            // c * (g^m)^(-1) mod n²
            const ui = (ciphertext * gmInv) % nn;
            console.log("ui:", ui.toString());

            uiVec.push(ui);
        }

        // Проверка уравнений (точно как в Python)
        console.log("\n=== Проверка уравнений ===");
        let result = true;
        for (let i = 0; i < numOfMessages; i++) {
            console.log(`\nПроверка для i=${i}:`);

            // z_i^n mod n²
            const ziN = modPow(z_vec[i], n, nn);
            console.log("ziN:", ziN.toString());

            // u_i^e_i mod n²
            const uiEi = modPow(uiVec[i], e_vec[i], nn);
            console.log("uiEi:", uiEi.toString());

            // a_i * u_i^e_i mod n²
            const rightSide = (a_vec[i] * uiEi) % nn;
            console.log("rightSide:", rightSide.toString());

            if (ziN !== rightSide) {
                console.log("\nПроверка не пройдена для i=" + i);
                console.log("ziN:", ziN.toString());
                console.log("rightSide:", rightSide.toString());
                result = false;
            }
            else {
                console.log("\nПроверка пройдена для i=" + i);
            }
        }

        console.log("\n=== Все проверки пройдены успешно ===");
        return result;
    }

    let proof;

    async function showConfirmation() {
        console.log("starting confirmation");
        const selectedOption = document.querySelector('input[name="vote"]:checked');
        if (!selectedOption) {
            alert('Пожалуйста, выберите вариант ответа');
            return;
        }

        const selectedIndex = parseInt(selectedOption.value);
        const messageToEncrypt = voteVariants[selectedIndex];
        console.log("messageToEncrypt: ", messageToEncrypt);

        // Генерируем доказательство и шифруем голос
        proof = await generateProof(publicKey.n, voteVariants, messageToEncrypt);

        // Показываем модальное окно подтверждения
        document.getElementById('confirmationModal').style.display = 'flex';
    }

    function hideConfirmation() {
        document.getElementById('confirmationModal').style.display = 'none';
    }

    // Функции для работы с base64
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToArrayBuffer(base64) {
        const binary_string = atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function bigIntToBase64(bigInt) {
        // Преобразуем BigInt в строку шестнадцатеричного формата
        const hex = bigInt.toString(16);
        // Добавляем ведущий ноль, если длина нечетная
        const paddedHex = hex.length % 2 ? '0' + hex : hex;

        // Преобразуем hex в массив байтов
        const bytes = new Uint8Array(paddedHex.length / 2);
        for (let i = 0; i < paddedHex.length; i += 2) {
            bytes[i / 2] = parseInt(paddedHex.slice(i, i + 2), 16);
        }

        // Кодируем в base64
        return btoa(String.fromCharCode.apply(null, bytes));
    }

    function base64ToBigInt(base64) {
        console.log("base64ToBigInt:", base64);
        // Декодируем base64 в бинарную строку
        const binaryString = atob(base64);

        // Преобразуем бинарную строку в массив байтов
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        // Преобразуем байты в шестнадцатеричную строку
        const hexString = Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');

        // Создаем BigInt из шестнадцатеричной строки
        return BigInt('0x' + hexString);
    }

    async function submitVote() {
        if (!proof) {
            console.error('Proof is not generated');
            return;
        }

        const blindedBallot = blindBallot(proof.ciphertext, rsaSignPublicKey);

        const resultBlind = await sendBlindedBallot(proof.ciphertext, blindedBallot, voting_id);

        if (resultBlind.success) {
            // Получили подпись, можно использовать result.signature
            console.log('Бюллетень успешно подписан:', resultBlind.signature.toString());
        } else {
            console.error('Ошибка при регистрации бюллетеня:', resultBlind.error);
        }


        const voteData = {
            voting_id: voting_id,
            encrypted_ballot: bigIntToBase64(proof.ciphertext),
            zkp_proof_e_vec: proof.e_vec.map(e => bigIntToBase64(e)),
            zkp_proof_z_vec: proof.z_vec.map(z => bigIntToBase64(z)),
            zkp_proof_a_vec: proof.a_vec.map(a => bigIntToBase64(a)),
            signature: bigIntToBase64(resultBlind.signature),
        };

        const result = await verify(proof.e_vec, proof.z_vec, proof.a_vec, proof.ciphertext, proof.valid_messages, publicKey.n);
        console.log("result:", result);

        try {
            const response = await fetch('/voting/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // для отправки куков
                body: JSON.stringify(voteData)
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            console.log('Success:', data);
            alert('Ваш голос успешно отправлен!');
            hideConfirmation();
        } catch (error) {
            console.error('Error:', error);
            alert('Произошла ошибка при отправке голоса: ' + error.message);
        }
    }

    async function testZKP() {
        console.log("=== Начало тестирования ZKP ===");

        // Создаем те же варианты голосов, что и в Python
        const voteVariants = [];
        for (let i = 0; i < 4; i++) {
            voteVariants.push(2n ** (30n * BigInt(i)));
        }
        console.log("Vote variants:", voteVariants.map(v => v.toString()));

        // Создаем тестовый голос (такой же как в Python)
        const testVote = 2n ** 30n; // 2^(30*1)
        console.log("Test vote:", testVote.toString());

        // Генерируем доказательство
        const proof = await generateProof(publicKey.n, voteVariants, testVote);
        console.log("\nGenerated proof:");
        console.log("e_vec:", proof.e_vec.map(e => e.toString()));
        console.log("z_vec:", proof.z_vec.map(z => z.toString()));
        console.log("a_vec:", proof.a_vec.map(a => a.toString()));
        console.log("ciphertext:", proof.ciphertext.toString());

        // Проверяем доказательство
        const isValid = await verify(
            proof.e_vec.map(e => BigInt(e)),
            proof.z_vec.map(z => BigInt(z)),
            proof.a_vec.map(a => BigInt(a)),
            BigInt(proof.ciphertext),
            voteVariants,
            publicKey.n
        );

        console.log("\nVerification result:", isValid);
        return isValid;
    }

    // Добавляем кнопку для тестирования
    const testButton = document.createElement('button');
    testButton.textContent = 'Тест ZKP';
    testButton.style.position = 'fixed';
    testButton.style.top = '10px';
    testButton.style.right = '10px';
    testButton.onclick = testZKP;
    document.body.appendChild(testButton);

    document.querySelector('.button').addEventListener('click', showConfirmation);
    document.querySelector('.modal-button.confirm').addEventListener('click', submitVote);
    document.querySelector('.modal-button.cancel').addEventListener('click', hideConfirmation);


    function blindBallot(ciphertext, publicKey) {
        // Преобразуем входные данные в BigInt
        const message = BigInt(ciphertext);
        const e = BigInt(publicKey.e);
        const n = BigInt(publicKey.n);

        // Выбираем случайное r, взаимно простое с n
        let r;
        do {
            // Генерируем случайное число от 2 до n-1
            const array = new Uint8Array(n.toString(2).length / 8 + 1);
            crypto.getRandomValues(array);
            r = BigInt('0x' + Array.from(array)
                .map(b => b.toString(16).padStart(2, '0'))
                .join('')) % (n - 2n) + 2n;
        } while (gcd(r, n) !== 1n);

        // Ослепляем сообщение: m' = m * r^e mod n
        const rPowE = modPow(r, e, n);
        const blindedMessage = (message * rPowE) % n;

        return {
            blindedMessage: blindedMessage,
            r: r
        };
    }

    async function sendBlindedBallot(ballot, blindedBallot, votingId) {
        try {
            // Преобразуем большие числа в base64 для безопасной передачи
            const ballotData = {
                voting_id: votingId,
                ballot: bigIntToBase64(ballot),
                blinded_ballot: bigIntToBase64(blindedBallot.blindedMessage),
                // Сохраняем r локально, оно понадобится позже для снятия ослепления
                r_base64: bigIntToBase64(blindedBallot.r)
            };

            const response = await fetch('/register_ballot', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // для отправки куков
                body: JSON.stringify(ballotData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            // Проверяем успешность операции
            if (result.success) {
                // Сохраняем подписанную ослепленную бюллетень
                const blindedSignature = base64ToBigInt(result.signature);

                console.log("blindedSignature:", blindedSignature.toString());

                // Снимаем ослепление
                const unblindedSignature = unblindSignature(
                    blindedSignature,
                    blindedBallot.r,
                    BigInt(rsaSignPublicKey.n)
                );

                console.log("unblindedSignature:", unblindedSignature.toString());

                const isVerified = verifySignature(ballot, unblindedSignature, rsaSignPublicKey);
                console.log("isVerified:", isVerified);



                return {
                    success: true,
                    signature: unblindedSignature
                };
            } else {
                throw new Error(result.error || 'Неизвестная ошибка при регистрации бюллетеня');
            }
        } catch (error) {
            console.error('Ошибка при отправке ослепленной бюллетени:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }


    function unblindSignature(blindedSignature, r, n) {
        // Вычисляем r^(-1) mod n
        const rInv = modInverse(r, n);
        // Снимаем ослепление: s = s' * r^(-1) mod n
        return blindedSignature * rInv % n;
    }


    function verifySignature(message, signature, rsaSignPublicKey) {
        const n = BigInt(rsaSignPublicKey.n);
        const e = BigInt(rsaSignPublicKey.e);
        const s = BigInt(signature);
        return message === modPow(s, e, n);
    }

};