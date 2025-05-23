import numpy as np
from numba import njit
from fuzzy_commitment.constants import N, Q

def crange(coeffs, q):
    """Center coefficients to range (−q/2, q/2]."""
    return np.where((coeffs >= 0) & (coeffs <= q//2), coeffs, coeffs - q)

def find_primitive_root(q: int) -> int:
    """Find a primitive root mod prime q."""
    def prime_factors(n):
        factors = set()
        while n % 2 == 0:
            factors.add(2); n //= 2
        p = 3
        while p * p <= n:
            while n % p == 0:
                factors.add(p); n //= p
            p += 2
        if n > 1:
            factors.add(n)
        return factors

    if q == 2:
        return 1
    phi = q - 1
    factors = prime_factors(phi)
    for g in range(2, q):
        if all(pow(g, phi // f, q) != 1 for f in factors):
            return g
    raise RuntimeError(f"No primitive root for {q}")

# Precompute for your fixed (N, Q)
GLOBAL_PSI     = pow(find_primitive_root(Q), (Q - 1) // (2 * N), Q)
GLOBAL_PSI_INV = pow(GLOBAL_PSI, Q - 2, Q)

@njit(cache=True)
def ntt(a: np.ndarray, psi: int, q: int) -> np.ndarray:
    """In-place forward Cooley–Tukey NTT mod q using psi."""
    n = a.size
    logn = int(np.log2(n))
    A = a.copy() % q

    # bit-reverse
    for i in range(n):
        rev = 0
        x = i
        for _ in range(logn):
            rev = (rev << 1) | (x & 1)
            x >>= 1
        if i < rev:
            A[i], A[rev] = A[rev], A[i]

    length = 2
    while length <= n:
        exp = n // length
        wlen = pow(psi, exp) % q
        half = length // 2
        for i in range(0, n, length):
            w = 1
            for j in range(i, i + half):
                u = A[j]
                v = (A[j + half] * w) % q
                A[j] = u + v if u + v < q else u + v - q
                A[j + half] = u - v if u - v >= 0 else u - v + q
                w = (w * wlen) % q
        length <<= 1

    return A

@njit(cache=True)
def intt(A: np.ndarray, psi_inv: int, q: int) -> np.ndarray:
    """In-place inverse NTT mod q using psi_inv, then scale by n^{-1}."""
    n = A.size
    a = ntt(A, psi_inv, q)
    inv_n = pow(n, q - 2) % q
    for i in range(n):
        a[i] = (a[i] * inv_n) % q
    return a

def negacyclic_convolution(a_coeffs, b_coeffs, q, psi):
    """Naïve fallback O(n^2) negacyclic convolution mod (x^n+1)."""
    n = a_coeffs.shape[0]
    res = np.zeros(n, dtype=np.int64)
    for i in range(n):
        for j in range(n):
            k = (i + j) % n
            sign = 1 if (i + j) < n else -1
            res[k] = (res[k] + sign * a_coeffs[i] * b_coeffs[j]) % q
    return crange(res, q)

def discrete_gaussian(n, q, std=1.0):
    """Sample discrete Gaussian noise (raw coeffs)."""
    return np.round(std * np.random.randn(n)).astype(np.int64) % q

def discrete_uniform(n, q):
    """Uniform sample (raw coeffs)."""
    return np.random.randint(0, q, size=n, dtype=np.int64)

def encode_bitstring_to_poly(bits, q):
    from .Rq import Rq as _Rq
    coeffs = np.array(bits, dtype=np.int64)
    return _Rq(coeffs, q)

def decode_poly_to_bitstring(poly, threshold=0):
    coeffs = poly.coeffs
    return (coeffs > threshold).astype(int).tolist()
