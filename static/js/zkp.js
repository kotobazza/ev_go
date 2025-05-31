import { modPow, modInverse, randomBigInt, gcd, computeDigest } from './math.js';

export async function generateProof(n, validMessages, messageToEncrypt) {
    const nn = BigInt(n) * BigInt(n);
    const numOfMessages = validMessages.length;

    let r;
    do {
        r = randomBigInt(n);
    } while (gcd(r, n) !== 1n);

    const g = n + 1n;
    const ciphertext = (modPow(g, messageToEncrypt, nn) * modPow(r, n, nn)) % nn;

    const uiVec = [];
    for (const m of validMessages) {
        const gm = modPow(g, m, nn);
        const gmInv = modInverse(gm, nn);
        const ui = (ciphertext * gmInv) % nn;
        uiVec.push(ui);
    }

    const B = 256;
    const twoToB = 2n ** 256n;

    const eiVec = [];
    const ziVec = [];
    for (let i = 0; i < numOfMessages - 1; i++) {
        eiVec.push(randomBigInt(twoToB));
        ziVec.push(randomBigInt(n));
    }

    const w = randomBigInt(n);
    const trueIndex = validMessages.findIndex(m => m === messageToEncrypt);

    if (trueIndex === -1) {
        console.log("trueIndex is -1");
        console.log(messageToEncrypt);
        console.log(validMessages);
        return;
    }

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

    const hash = await computeDigest(aiVec);
    const chal = hash % twoToB;


    let eiSum = 0n;
    for (const ei of eiVec) {
        eiSum = (eiSum + ei) % twoToB;
    }

    const ei = (chal - eiSum + twoToB) % twoToB;

    const riEi = modPow(r, ei, n);
    const zi = (w * riEi) % n;

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

export async function verify(e_vec, z_vec, a_vec, ciphertext, valid_messages, n) {
    console.log("Проверка всех доказательств");
    const numOfMessages = valid_messages.length;
    const B = 256;
    const twoToB = BigInt(2) ** BigInt(B);
    const nn = n * n;
    const g = n + 1n;



    const hash = await computeDigest(a_vec);
    const chal = hash % twoToB;


    let eiSum = 0n;
    for (const e of e_vec) {
        eiSum = (eiSum + e) % twoToB;
    }

    if (chal !== eiSum) {
        console.log("chal: " + chal.toString(10));
        console.log("eiSum: " + eiSum.toString(10));
        return false;
    }

    const uiVec = [];
    for (let i = 0; i < valid_messages.length; i++) {
        const m = valid_messages[i];
        const gm = modPow(g, m, nn);
        const gmInv = modInverse(gm, nn);

        const ui = (ciphertext * gmInv) % nn;
        uiVec.push(ui);
    }


    let result = true;
    for (let i = 0; i < numOfMessages; i++) {
        const ziN = modPow(z_vec[i], n, nn);
        const uiEi = modPow(uiVec[i], e_vec[i], nn);
        const rightSide = (a_vec[i] * uiEi) % nn;



        if (ziN !== rightSide) {
            console.log("ziN: " + ziN.toString(10));
            console.log("rightSide: " + rightSide.toString(10));
            result = false;
        }
    }

    console.log("\n=== Все проверки пройдены успешно ===");
    return result;
}