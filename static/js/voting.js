import { modPow, bigIntToBase64, base64ToBigInt, computeDigest } from './math.js';
import { blindBallot, unblindSignature, verifySignature } from './rsa.js';
import { generateProof, verify } from './zkp.js';
import { getUserData, userToNonce } from './profile.js';

export const EV_STATE = {
    EV_STATIC_PARAMS: null,
    user: getUserData(),
    nonce: null,
    vote_variants: null,
    enc_vote: null,
    zkp_proof: null,
    label: null,
    label_sig: null,
}


export function generateVoteVariants(base, options_amount, pailierPublicKey) {
    const voteVariants = [];
    for (let i = 0; i < options_amount; i++) {
        voteVariants.push(modPow(2n, base * BigInt(i), pailierPublicKey.n ** 2n));
    }
    return voteVariants;
}

function showConfirmation() {
    const selectedOption = document.querySelector('input[name="vote"]:checked');
    if (!selectedOption) {
        alert('Пожалуйста, выберите вариант ответа');
        return;
    }

    document.getElementById('confirmationModal').style.display = 'flex';
}

function hideConfirmation() {
    document.getElementById('confirmationModal').style.display = 'none';
}


export async function initializeVoting(params) {
    const { voting_id, options_amount, pailierPublicKey, rsaSignPublicKey, challenge_bits, base } = params;

    EV_STATE.EV_STATIC_PARAMS = params;
    EV_STATE.vote_variants = generateVoteVariants(base, options_amount, pailierPublicKey);



    async function showVotingProcess() {
        document.querySelectorAll('.step.active').forEach(step => step.classList.remove('active'));
        document.querySelectorAll('.step.completed').forEach(step => step.classList.remove('completed'));

        const votingProcess = document.getElementById('votingProcess');
        votingProcess.style.display = 'block';
        setTimeout(() => {
            votingProcess.classList.remove('visible');
        }, 50);

        setTimeout(() => {
            votingProcess.classList.add('visible');
        }, 50);

        // Деактивируем форму голосования и кнопки
        const form = document.getElementById('votingForm');
        const inputs = form.querySelectorAll('input[type="radio"]');
        inputs.forEach(input => input.disabled = true);
        document.querySelector('.button.processVotingButton').disabled = true;

        updateStep('step1', 'Шифрование вашего голоса...');

        await prepareVote();

        updateStep('step1', 'Шифрование вашего голоса...', true);

        updateStep('step2', 'Запрос подписи у Регистратора...');

        await signBallotByRegistrator();

        updateStep('step2', 'Запрос подписи у Регистратора...', true);

        updateStep('step3', 'Отправка бюллетеня Счетчику...');

        await submitVote();

        updateStep('step3', 'Отправка бюллетеня Счетчику...', true);
    }


    function updateStep(stepId, status, isCompleted = false) {
        const step = document.getElementById(stepId);
        const statusEl = step.querySelector('.step-status');

        // Обновляем статус
        statusEl.textContent = status;

        // Обновляем классы
        step.classList.remove('active');
        if (isCompleted) {
            step.classList.add('completed');
        } else {
            step.classList.add('active');
        }
    }

    async function prepareVote() {
        const selectedOption = document.querySelector('input[name="vote"]:checked');
        if (!selectedOption) {
            alert('Пожалуйста, выберите вариант ответа');
            return;
        }

        const selectedIndex = parseInt(selectedOption.value);
        const messageToEncrypt = EV_STATE.vote_variants[selectedIndex];
        EV_STATE.zkp_proof = await generateProof(pailierPublicKey.n, EV_STATE.vote_variants, messageToEncrypt);
        console.log("EV_STATE.zkp_proof: ", EV_STATE.zkp_proof);
    }

    async function signBallotByRegistrator() {
        if (!EV_STATE.zkp_proof) {
            console.error('ZKP-доказательство не сгенерировано');
            return;
        }

        EV_STATE.nonce = userToNonce(EV_STATE.user);
        const ciphertext = EV_STATE.zkp_proof.ciphertext;

        EV_STATE.label = await computeDigest([EV_STATE.nonce, ciphertext]);

        const { rsaSignPublicKey } = EV_STATE.EV_STATIC_PARAMS;

        const blindedBallotData = blindBallot(EV_STATE.label, rsaSignPublicKey);


        const resultBlind = await sendBlindedBallot(blindedBallotData);

        if (!resultBlind.success) {
            console.error('Не удалось получить подпись от регистратора');
            return;
        }

        const isVerified = verifySignature(EV_STATE.label, resultBlind.signature, rsaSignPublicKey);
        if (!isVerified) {
            console.error('Ошибка верификации подписи регистратора');
            return;
        }

        EV_STATE.label_sig = resultBlind.signature;

        // Показываем подпись
        const step2Details = document.querySelector('#step2 .step-details');
        step2Details.style.display = 'block';
        const signaturePreview = document.querySelector('#step2 .signature-preview');
        signaturePreview.textContent = bigIntToBase64(resultBlind.signature).substring(0, 20) + '...';
    }

    async function submitVote() {
        if (!EV_STATE.zkp_proof || !EV_STATE.label || !EV_STATE.label_sig) {
            console.error('Недостаточно данных для отправки голосования');
            return;
        }

        const { rsaSignPublicKey } = EV_STATE.EV_STATIC_PARAMS;



        const isVerified = verifySignature(EV_STATE.label, EV_STATE.label_sig, rsaSignPublicKey);
        if (!isVerified) {
            return;
        }

        // Показываем подпись
        const step2Details = document.querySelector('#step2 .step-details');
        step2Details.style.display = 'block';
        const signaturePreview = document.querySelector('#step2 .signature-preview');
        signaturePreview.textContent = bigIntToBase64(EV_STATE.label_sig).substring(0, 20) + '...';

        // Завершаем второй шаг
        updateStep('step2', 'Подпись получена', true);


        const voteData = {
            voting_id: EV_STATE.EV_STATIC_PARAMS.voting_id,
            encrypted_ballot: bigIntToBase64(EV_STATE.zkp_proof.ciphertext),
            zkp_proof_e_vec: EV_STATE.zkp_proof.e_vec.map(e => bigIntToBase64(e)),
            zkp_proof_z_vec: EV_STATE.zkp_proof.z_vec.map(z => bigIntToBase64(z)),
            zkp_proof_a_vec: EV_STATE.zkp_proof.a_vec.map(a => bigIntToBase64(a)),
            signature: bigIntToBase64(EV_STATE.label_sig),
            label: bigIntToBase64(EV_STATE.label),
        };

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

            // Показываем ответ счетчика
            const step3Details = document.querySelector('#step3 .step-details');
            step3Details.style.display = 'block';
            const counterResponse = document.querySelector('#step3 .counter-response');
            counterResponse.textContent = JSON.stringify(data).substring(0, 50) + '...';

            // Завершаем третий шаг
            updateStep('step3', 'Бюллетень принят', true);

            // Показываем результат
            const votingResult = document.querySelector('.voting-result');
            votingResult.style.display = 'block';

            // Генерируем QR-код
            const labelBase64 = bigIntToBase64(EV_STATE.label);
            QRCode.toCanvas(document.getElementById('qrCode'), labelBase64, function (error) {
                if (error) console.error(error);
            });

            // Показываем лейбл
            document.querySelector('.label-preview').textContent = labelBase64;

            // Блокируем кнопку отправки
            document.querySelector('.button.sendVoteButton').setAttribute('disabled', 'disabled');

        } catch (error) {
            updateStep('step3', 'Ошибка: ' + error.message);
            console.error('Error:', error);
        }
    }




    async function sendBlindedBallot(blindedBallotData) {
        try {
            const ballotData = {
                voting_id: String(EV_STATE.EV_STATIC_PARAMS.voting_id),
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

    // Инициализация UI и обработчиков событий
    function initializeUI() {

        // Обработчики событий для кнопок
        const processVotingButton = document.querySelector('.button.processVotingButton');
        const confirmButton = document.querySelector('.modal-button.confirm');
        const cancelButton = document.querySelector('.modal-button.cancel');

        // Когда нажимаем "Отправить голос"
        processVotingButton.addEventListener('click', showConfirmation);

        // Обработка подтверждения
        confirmButton.addEventListener('click', async () => {
            hideConfirmation();
            await showVotingProcess();
        });

        // Отмена
        cancelButton.addEventListener('click', hideConfirmation);
    }

    initializeUI();
}
