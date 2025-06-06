import { modPow, modInverse, bigIntToBase64, base64ToBigInt, computeDigest } from './math.js';



export function verifyValue(C, r_prime, n) {
    const R = C % n;
    return modPow(r_prime, n, n) == R;
}

export function compute_m_from_proof(C, r_prime, n) {
    const N_squared = n * n;
    const r_prime_inv_N = modPow(r_prime, -n, N_squared);
    const numerator = (C * r_prime_inv_N) % N_squared;
    const m = ((numerator - 1) / n) % n;
    return m;
}