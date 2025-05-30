export function gcd(a, b) {
    a = BigInt(a);
    b = BigInt(b);

    while (b !== 0n) {
        [a, b] = [b, a % b];
    }

    return a;
}

export function lcm(a, b) {
    a = BigInt(a);
    b = BigInt(b);

    if (a === 0n || b === 0n) {
        return 0n;
    }

    const absProduct = (a * b) < 0n ? -(a * b) : a * b;
    const gcdValue = gcd(a, b);

    return absProduct / BigInt(gcdValue);
}

export function L(x, n) {
    return (x - 1n) / n;
}

export function modPow(base, exponent, modulus) {
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

export function modInverse(a, m) {
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

export function randomBigInt(max) {
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

export function checkBigIntRange(value, modulus) {
    if (value < 0n || value >= modulus) {
        return false;
    }
    return true;
}


export function bigIntToBase64(bigInt) {
    const decimalStr = bigInt.toString(10);
    return btoa(decimalStr);
}

export function base64ToBigInt(base64) {
    return BigInt(atob(base64));
}

export async function computeDigest(values) {
    const encoder = new TextEncoder();
    let data = new Uint8Array(0);
    for (let i = 0; i < values.length; i++) {
        const val = values[i];
        const base64Data = bigIntToBase64(val) + "|";
        const chunk = encoder.encode(base64Data);
        const newData = new Uint8Array(data.length + chunk.length);
        newData.set(data);
        newData.set(chunk, data.length);
        data = newData;
    }

    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));


    let decimalString = '';
    for (const byte of hashArray) {
        decimalString += byte.toString().padStart(3, '0');
    }

    const result = BigInt(decimalString);
    return result;
}