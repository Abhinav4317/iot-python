import numpy as np
from .utils import crange, GLOBAL_PSI, GLOBAL_PSI_INV, ntt, intt, negacyclic_convolution

class Rq:
    """
    Element of R_q = Z_q[x] / (x^n + 1).
    """

    def __init__(self, coeffs, q):
        coeffs = np.array(coeffs, dtype=np.int64) % q
        self.q = q
        self.n = coeffs.size
        self.coeffs = crange(coeffs, q)
        # Use precomputed roots:
        self.psi     = GLOBAL_PSI
        self.psi_inv = GLOBAL_PSI_INV

    def __repr__(self):
        return f"Rq({self.coeffs.tolist()}, mod {self.q})"

    def __add__(self, other):
        return Rq((self.coeffs + other.coeffs) % self.q, self.q)

    def __rmul__(self, scalar):
        return Rq((self.coeffs * int(scalar)) % self.q, self.q)

    def __mul__(self, other):
        # fallback direct convolution
        c = negacyclic_convolution(self.coeffs, other.coeffs, self.q, self.psi)
        return Rq(c, self.q)

    def __pow__(self, exp):
        if exp == 0:
            return Rq([1] + [0]*(self.n-1), self.q)
        result = self
        for _ in range(exp-1):
            result = result * self
        return result

    def to_ntt(self):
        """Forward NTT to coefficient domain → NTT domain."""
        return ntt(self.coeffs, self.psi, self.q)

    @staticmethod
    def from_ntt(A, psi_inv, q):
        """Inverse NTT from domain → coefficient polynomial."""
        coeffs = intt(A, psi_inv, q)
        return Rq(coeffs, q)
