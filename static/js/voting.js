import { modPow, bigIntToBase64, base64ToBigInt, computeDigest } from './math.js';
import { blindBallot, unblindSignature, verifySignature } from './rsa.js';
import { generateProof, verify } from './zkp.js';
import { getUserData } from './profile.js';

export function initializeVoting(params) {
    const { voting_id, options_amount, pailierPublicKey, rsaSignPublicKey, challenge_bits, base, vote_variants, user } = params;





    async function userToNonce(user) {
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

    async function showConfirmation() {
        console.log("starting confirmation");
        const selectedOption = document.querySelector('input[name="vote"]:checked');
        if (!selectedOption) {
            alert('Пожалуйста, выберите вариант ответа');
            return;
        }

        const selectedIndex = parseInt(selectedOption.value);
        const messageToEncrypt = voteVariants[selectedIndex];


        proof = await generateProof(pailierPublicKey.n, voteVariants, messageToEncrypt);
        document.getElementById('confirmationModal').style.display = 'flex';
    }

    function hideConfirmation() {
        document.getElementById('confirmationModal').style.display = 'none';
    }

    // async function signBallotByRegistrator() {
    //     console.log("starting signBallotByRegistrator");
    //     const selectedOption = document.querySelector('input[name="vote"]:checked');
    //     if (!selectedOption) {
    //         alert('Пожалуйста, выберите вариант ответа');
    //         return;
    //     }
    // }



    async function submitVote() {
        if (!proof) {
            console.error('Proof is not generated');
            return;
        }

        const ciphertext = proof.ciphertext;

        const nonce = await userToNonce(user);

        EV_STATE.label = await computeDigest([nonce, ciphertext]);


        const blindedBallotData = blindBallot(EV_STATE.label, rsaSignPublicKey);
        const resultBlind = await sendBlindedBallot(blindedBallotData, voting_id);


        const isVerified = verifySignature(EV_STATE.label, resultBlind.signature, rsaSignPublicKey);
        if (!isVerified) {
            console.error("Blind signature is not valid");
            return;
        }

        if (resultBlind.success) {
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
            label: bigIntToBase64(EV_STATE.label),
        };


        console.log("verify blind signature:", verifySignature(proof.ciphertext, resultBlind.signature, rsaSignPublicKey));
        console.log("voteData: ", voteData);

        const result = await verify(proof.e_vec, proof.z_vec, proof.a_vec, proof.ciphertext, proof.valid_messages, pailierPublicKey.n);
        if (!result) {
            console.error("ZKP proof is not valid");
            return;
        }

        try {
            const response = await fetch('/ballot/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(voteData)
            });

            if (!response.ok) {
                throw new Error('Network response was not ok');
            }

            const data = await response.json();
            console.log('Sending success:', data);
            alert('Ваш голос успешно отправлен!');
            hideConfirmation();
        } catch (error) {
            console.error('Error:', error);
            alert('Произошла ошибка при отправке голоса: ' + error.message);
        }
    }

    async function testZKP() {
        console.log("=== Начало тестирования ZKP ===");
        const testVoteVariants = [];
        for (let i = 0; i < 4; i++) {
            testVoteVariants.push(2n ** (30n * BigInt(i)));
        }

        const testVote = 2n ** 30n;
        const testProof = await generateProof(pailierPublicKey.n, testVoteVariants, testVote);

        const isValid = await verify(
            testProof.e_vec.map(e => BigInt(e)),
            testProof.z_vec.map(z => BigInt(z)),
            testProof.a_vec.map(a => BigInt(a)),
            BigInt(testProof.ciphertext),
            testVoteVariants,
            pailierPublicKey.n
        );

        console.log("\nVerification result:", isValid);
        return isValid;
    }

    async function sendBlindedBallot(blindedBallotData, votingId) {
        try {
            const ballotData = {
                voting_id: String(votingId),
                blinded_ballot: bigIntToBase64(blindedBallotData.blindedMessage),
            };

            const response = await fetch('/ballot/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(ballotData)
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            if (result.success) {
                const blindedSignature = base64ToBigInt(result.signature);
                const unblindedSignature = unblindSignature(
                    blindedSignature,
                    blindedBallotData.r,
                    BigInt(rsaSignPublicKey.n)
                );

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

    // Инициализация UI
    const testButton = document.createElement('button');
    testButton.textContent = 'Тест ZKP';
    testButton.style.position = 'fixed';
    testButton.style.top = '10px';
    testButton.style.right = '10px';
    testButton.onclick = testZKP;
    document.body.appendChild(testButton);

    document.querySelector('.button.sendVoteButton').addEventListener('click', showConfirmation);
    document.querySelector('.modal-button.confirm').addEventListener('click', submitVote);
    document.querySelector('.button.sendVoteButton').addEventListener('click', submitVote).setAttribute('disabled', true);
    document.querySelector('.modal-button.cancel').addEventListener('click', hideConfirmation);
    document.querySelector('.button.signBallotByRegistrator').addEventListener('click', signBallotByRegistrator);
}
