import { modPow, bigIntToBase64, base64ToBigInt, computeDigest } from './math.js';
import { blindBallot, unblindSignature, verifySignature } from './rsa.js';
import { generateProof, verify } from './zkp.js';

export function initializeVoting(params) {
    const { voting_id, options_amount, pailierPublicKey, rsaSignPublicKey } = params;
    console.log("rsaSignPublicKey: ", rsaSignPublicKey);
    console.log("pailierPublicKey: ", pailierPublicKey);
    console.log("options_amount: ", options_amount);

    // Генерация вариантов голосования
    const voteVariants = [];
    for (let i = 0; i < options_amount; i++) {
        voteVariants.push(modPow(2n, 30n * BigInt(i), pailierPublicKey.n ** 2n));
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

        proof = await generateProof(pailierPublicKey.n, voteVariants, messageToEncrypt);
        document.getElementById('confirmationModal').style.display = 'flex';
    }

    function hideConfirmation() {
        document.getElementById('confirmationModal').style.display = 'none';
    }

    async function submitVote() {
        if (!proof) {
            console.error('Proof is not generated');
            return;
        }

        const blindedBallotData = blindBallot(proof.ciphertext, rsaSignPublicKey);
        const resultBlind = await sendBlindedBallot(proof.ciphertext, blindedBallotData, voting_id);

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

    async function sendBlindedBallot(ballot, blindedBallotData, votingId) {
        try {
            const ballotData = {
                voting_id: String(votingId),
                ballot: bigIntToBase64(ballot),
                blinded_ballot: bigIntToBase64(blindedBallotData.blindedMessage),
                r_base64: bigIntToBase64(blindedBallotData.r)
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

                const isVerified = verifySignature(ballot, unblindedSignature, rsaSignPublicKey);

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

    document.querySelector('.button').addEventListener('click', showConfirmation);
    document.querySelector('.modal-button.confirm').addEventListener('click', submitVote);
    document.querySelector('.modal-button.cancel').addEventListener('click', hideConfirmation);
}