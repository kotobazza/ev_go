import { modPow, bigIntToBase64, base64ToBigInt, computeDigest } from './math.js';
import { blindBallot, unblindSignature, verifySignatureWithMultiplier } from './rsa.js';
import { generateProof, verify } from './zkp.js';
import { getUserData, userToNonce, getOldVotingParams } from './profile.js';
import QRCode from "https://esm.sh/qrcode@1.5.3";

export const EV_STATE = {
    EV_STATIC_PARAMS: null,
    user: getUserData(),
    nonce: null,
    vote_variants: null,
    enc_vote: null,
    zkp_proof: null,
    label: null,
    label_sig: null,
    oldVotingParams: null,
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


function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function initializeVoting(params) {
    const { voting_id, options_amount, pailierPublicKey, rsaSignPublicKey, challenge_bits, base } = params;

    EV_STATE.EV_STATIC_PARAMS = params;
    EV_STATE.vote_variants = generateVoteVariants(base, options_amount, pailierPublicKey);

    EV_STATE.oldVotingParams = getOldVotingParams(voting_id);

    console.log("EV_STATE.oldVotingParams: ", EV_STATE.oldVotingParams);


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

        updateStep('step1', 'Шифрование вашего голоса...', 1);
        await delay(1000);

        const isPrepared = await prepareVote();
        if (!isPrepared) {
            updateStep('step1', 'Ошибка шифрования вашего голоса...', 3);
            return false;
        }

        updateStep('step1', 'Шифрование вашего голоса завершено!', 2);

        updateStep('step2', 'Запрос подписи у Регистратора...', 1);
        await delay(1000);


        const isSigned = await signBallotByRegistrator();
        if (!isSigned) {
            updateStep('step2', 'Ошибка получения подписи у Регистратора...', 3);
            return false;
        }

        updateStep('step2', 'Подпись получена!', 2);

        updateStep('step3', 'Отправка бюллетеня Счетчику...', 1);
        await delay(1000);

        const isSubmitted = await submitVote();
        if (!isSubmitted) {
            updateStep('step3', 'Ошибка отправки бюллетеня Счетчику...', 3);
            return false;
        }

        updateStep('step3', 'Бюллетень отправлен!', 2);
    }


    function updateStep(stepId, status, state = 0) {
        const step = document.getElementById(stepId);
        const statusEl = step.querySelector('.step-status');

        // Обновляем статус
        statusEl.textContent = status;

        if (state == 0) {
            step.classList.remove('active');
            step.classList.remove('completed');
            step.classList.remove('error');
        } else if (state == 1) {
            step.classList.add('active');
            step.classList.remove('error');
            step.classList.remove('completed');
        } else if (state == 2) {
            step.classList.add('completed');
            step.classList.remove('error');
            step.classList.remove('active');
        } else if (state == 3) {
            step.classList.add('error');
            step.classList.remove('active');
            step.classList.remove('completed');

        }
    }

    async function prepareVote() {
        const selectedOption = document.querySelector('input[name="vote"]:checked');
        if (!selectedOption) {
            alert('Пожалуйста, выберите вариант ответа');
            return false;
        }

        const selectedIndex = parseInt(selectedOption.value);
        const messageToEncrypt = EV_STATE.vote_variants[selectedIndex];
        EV_STATE.zkp_proof = await generateProof(pailierPublicKey.n, EV_STATE.vote_variants, messageToEncrypt);
        console.log("EV_STATE.zkp_proof: ", EV_STATE.zkp_proof);

        return true
    }

    async function signBallotByRegistrator() {
        if (!EV_STATE.zkp_proof) {
            const errorMessage = document.querySelector('#step2 .error-message');
            errorMessage.textContent = 'ZKP-доказательство не сгенерировано';
            errorMessage.style.display = 'block';
            return false;
        }

        EV_STATE.nonce = await userToNonce(EV_STATE.user);
        const ciphertext = EV_STATE.zkp_proof.ciphertext;
        console.log("EV_STATE.nonce: ", EV_STATE.nonce);

        EV_STATE.label = await computeDigest([EV_STATE.nonce, ciphertext]);


        const { rsaSignPublicKey } = EV_STATE.EV_STATIC_PARAMS;

        const blindedBallotData = blindBallot(EV_STATE.label, rsaSignPublicKey);


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

            const result = await response.json();

            if (!response.ok) {
                const errorMessage = document.querySelector('#step2 .error-message');
                errorMessage.textContent = `${result.message}`;
                errorMessage.style.display = 'block';
                throw new Error(`HTTP error! status: ${response.status}`);
            }



            console.log("result: ", result);


            if (!result.success) {
                const errorMessage = document.querySelector('#step2 .error-message');
                errorMessage.textContent = result.error || 'Неизвестная ошибка при регистрации бюллетеня';
                errorMessage.style.display = 'block';
                return false;
            }

            const blindedSignature = base64ToBigInt(result.signature);
            const unblindedSignature = unblindSignature(
                blindedSignature,
                blindedBallotData.r,
                BigInt(rsaSignPublicKey.n)
            );

            const isVerified = verifySignatureWithMultiplier(EV_STATE.label, unblindedSignature, rsaSignPublicKey, EV_STATE.EV_STATIC_PARAMS.re_voting_multiplier);


            if (!isVerified) {
                const errorMessage = document.querySelector('#step2 .error-message');
                errorMessage.textContent = "Ошибка верификации подписи регистратора на клиенте";
                errorMessage.style.display = 'block';
                return false;
            }

            EV_STATE.label_sig = unblindedSignature;

            // Показываем подпись
            const step2Details = document.querySelector('#step2 .step-details');
            step2Details.style.display = 'block';
            const signaturePreview = document.querySelector('#step2 .signature-preview');
            signaturePreview.textContent = bigIntToBase64(unblindedSignature).substring(0, 20) + '...';
            return true;
        } catch (error) {
            console.error('Ошибка при отправке ослепленной бюллетени:', error);
            return false;
        }
    }

    async function submitVote() {
        if (!EV_STATE.zkp_proof || !EV_STATE.label || !EV_STATE.label_sig) {
            const errorMessage = document.querySelector('#step3 .error-message');
            errorMessage.textContent = "Не найдены все нужные данные для отправки голосования";
            errorMessage.style.display = 'block';
            return false;
        }

        const { rsaSignPublicKey } = EV_STATE.EV_STATIC_PARAMS;

        const isVerified = verifySignatureWithMultiplier(EV_STATE.label, EV_STATE.label_sig, rsaSignPublicKey, EV_STATE.EV_STATIC_PARAMS.re_voting_multiplier);
        if (!isVerified) {
            const errorMessage = document.querySelector('#step3 .error-message');
            errorMessage.textContent = "Ошибка верификации подписи регистратора на клиенте";
            errorMessage.style.display = 'block';
            return false;
        }

        const voteData = {
            voting_id: EV_STATE.EV_STATIC_PARAMS.voting_id,
            encrypted_ballot: bigIntToBase64(EV_STATE.zkp_proof.ciphertext),
            zkp_proof_e_vec: EV_STATE.zkp_proof.e_vec.map(e => bigIntToBase64(e)),
            zkp_proof_z_vec: EV_STATE.zkp_proof.z_vec.map(z => bigIntToBase64(z)),
            zkp_proof_a_vec: EV_STATE.zkp_proof.a_vec.map(a => bigIntToBase64(a)),
            signature: bigIntToBase64(EV_STATE.label_sig),
            label: bigIntToBase64(EV_STATE.label),
            old_label: EV_STATE.oldVotingParams?.oldLabel,
            old_nonce: EV_STATE.oldVotingParams?.oldNonce,
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
                const errorMessage = document.querySelector('#step3 .error-message');
                errorMessage.textContent = `Ошибка отправки бюллетеня Счетчику: ${response.status}`;
                errorMessage.style.display = 'block';
                throw new Error(`Ошибка отправки бюллетеня Счетчику: ${response.status}`);
            }

            const data = await response.json();

            // Показываем ответ счетчика
            const step3Details = document.querySelector('#step3 .step-details');
            step3Details.style.display = 'block';
            const counterResponse = document.querySelector('#step3 .counter-response');
            counterResponse.textContent = JSON.stringify(data).substring(0, 50) + '...';

            // Показываем результат
            const votingResult = document.querySelector('.voting-result');
            votingResult.style.display = 'block';

            // Генерируем QR-код
            const labelBase64 = bigIntToBase64(EV_STATE.label);
            try {
                const canvas = document.getElementById('qrcode');
                QRCode.toCanvas(canvas, labelBase64, function (error) {
                    if (error) console.error(error);
                    else console.log('QR-код сгенерирован!');
                });
            } catch (error) {
                console.error('Ошибка генерации QR-кода:', error);
            }

            // Показываем лейбл
            document.querySelector('.label-new').textContent = labelBase64;
            const nonceBase64 = await bigIntToBase64(EV_STATE.nonce);

            // Генерируем куку с Label и Nonce как подтверждение голосования
            console.log("labelBase64: ", labelBase64);
            console.log("nonceBase64: ", nonceBase64);
            document.cookie = `oldLabel_${EV_STATE.EV_STATIC_PARAMS.voting_id}=${labelBase64}; path=/; max-age=86400; samesite=strict`;
            document.cookie = `oldNonce_${EV_STATE.EV_STATIC_PARAMS.voting_id}=${nonceBase64}; path=/; max-age=86400; samesite=strict`;


            return true
        } catch (error) {
            console.error('Error:', error);
            return false
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

        if (EV_STATE.oldVotingParams) {
            processVotingButton.textContent = "Отправить голос повторно";

            const previousVote = document.querySelector('.previous-vote');
            previousVote.style.display = 'block';


            document.querySelector('.previous-vote-label-preview').textContent = EV_STATE.oldVotingParams.oldLabel;

            try {
                const canvas = document.getElementById('previous-vote-qr');
                QRCode.toCanvas(canvas, EV_STATE.oldVotingParams.oldLabel, function (error) {
                    if (error) console.error(error);
                    else console.log('QR-код сгенерирован!');
                });
            } catch (error) {
                console.error('Ошибка генерации QR-кода:', error);
            }

        }

        // Обработка подтверждения
        confirmButton.addEventListener('click', async () => {
            hideConfirmation();
            const previousVote = document.querySelector('.previous-vote');
            previousVote.style.display = 'none';

            await showVotingProcess();
        });

        // Отмена
        cancelButton.addEventListener('click', hideConfirmation);
    }

    initializeUI();
}
