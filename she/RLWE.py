import numpy as np
from .Rq import Rq
from .utils import discrete_gaussian, discrete_uniform

class RLWE:
    """
    RLWE helper:
      - generate_keys() → mk, (a, b)
      - rlwe_sample_commitments(a,b) → (v, u, t)
    """

    def __init__(self, n, q, t, std):
        assert (q - 1) % (2 * n) == 0, "q must satisfy q ≡ 1 mod 2n"
        self.n = n; self.q = q; self.t = t; self.std = std
        self.A_ntt = None
        self.B_ntt = None

    def generate_keys(self):
        """Return (mk, (a, b = a·mk + e))."""
        # sample raw arrays, then wrap
        mk_arr = discrete_gaussian(self.n, self.q, std=self.std)
        a_arr  = discrete_uniform(self.n, self.q)
        e_arr  = discrete_gaussian(self.n, self.q, std=self.std)

        mk = Rq(mk_arr, self.q)
        a  = Rq(a_arr, self.q)
        e  = Rq(e_arr, self.q)
        b  = a * mk + e

        # cache NTT-domain polynomials
        self.A_ntt = a.to_ntt()
        self.B_ntt = b.to_ntt()
        return mk, (a, b)

    def rlwe_sample_commitments(self, a, b):
        """Return (v, u = a·v + e1, t = b·v + e2)."""
        # fresh noise & secret (raw arrays → Rq)
        v = Rq(discrete_gaussian(self.n, self.q, std=self.std), self.q)
        e1 = Rq(discrete_gaussian(self.n, self.q, std=self.std), self.q)
        e2 = Rq(discrete_gaussian(self.n, self.q, std=self.std), self.q)

        if self.A_ntt is not None and self.B_ntt is not None:
            V_ntt = v.to_ntt()
            U = np.mod(self.A_ntt * V_ntt, self.q)
            u = Rq.from_ntt(U, v.psi_inv, self.q) + e1
            T = np.mod(self.B_ntt * V_ntt, self.q)
            t = Rq.from_ntt(T, v.psi_inv, self.q) + e2
            return v, u, t

        # fallback
        u = a * v + e1
        t = b * v + e2
        return v, u, t

    def encode_message(self, bits):
        from .utils import encode_bitstring_to_poly
        return encode_bitstring_to_poly(bits, self.q)

    def decode_message(self, poly):
        from .utils import decode_poly_to_bitstring
        return decode_poly_to_bitstring(poly)

    def load_public_parameters(self, a: Rq, b: Rq):
        """
        Precompute and cache the NTT of the public polynomials a and b.
        Call this once before rlwe_sample_commitments().
        """
        # forward‐NTT of a and b into the plan’s domain
        self.A_ntt = a.ntt()
        self.B_ntt = b.ntt()
        self._plan = a.plan