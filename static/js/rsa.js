import { modPow, modInverse, gcd, randomBigInt } from './math.js';

export function blindBallot(ciphertext, publicKey) {
    const message = BigInt(ciphertext);
    const e = BigInt(publicKey.e);
    const n = BigInt(publicKey.n);

    let r;
    do {
        const array = new Uint8Array(n.toString(2).length / 8 + 1);
        crypto.getRandomValues(array);
        r = BigInt('0x' + Array.from(array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')) % (n - 2n) + 2n;
    } while (gcd(r, n) !== 1n);

    const rPowE = modPow(r, e, n);
    const blindedMessage = (message * rPowE) % n;

    return {
        blindedMessage: blindedMessage,
        r: r
    };
}

export function unblindSignature(blindedSignature, r, n) {
    const rInv = modInverse(r, n);
    const unblindedSignature = (blindedSignature * rInv) % n;
    return unblindedSignature;
}

export function verifySignature(message, signature, rsaSignPublicKey) {
    const n = BigInt(rsaSignPublicKey.n);
    const e = BigInt(rsaSignPublicKey.e);
    const s = BigInt(signature);
    const calculatedMessage = modPow(s, e, n);
    return message === calculatedMessage;
}


export function verifySignatureWithMultiplier(message, signature, rsaSignPublicKey, multiplier) {
    return verifySignature(message, signature, rsaSignPublicKey) || verifySignature(message * multiplier, signature, rsaSignPublicKey);
}