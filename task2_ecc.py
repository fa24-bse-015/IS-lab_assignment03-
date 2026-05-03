"""
IS Lab Assignment
Task 2: Elliptic Curve Cryptography (ECC) Basics
Objective: Understand ECC key generation and encryption
"""


class EllipticCurve:
    """
    Elliptic curve over finite field F_p.
    Curve equation: y^2 = x^3 + ax + b  (mod p)

    Parameters used:
      p = 17  (prime modulus)
      a = 2, b = 2
      Generator G = (5, 1)
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, point):
        """Check if a point satisfies the curve equation."""
        if point is None:
            return True
        x, y = point
        lhs = (y * y) % self.p
        rhs = (x**3 + self.a * x + self.b) % self.p
        return lhs == rhs

    def mod_inverse(self, k):
        """Modular inverse using Fermat's Little Theorem: k^(p-2) mod p."""
        return pow(k, self.p - 2, self.p)

    def point_addition(self, P, Q):
        """
        Adds two distinct points P and Q on the curve.
        Formula:
          lambda = (y2 - y1) / (x2 - x1)  mod p
          x3 = lambda^2 - x1 - x2          mod p
          y3 = lambda*(x1 - x3) - y1       mod p
        """
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if P == Q:
            return self.point_doubling(P)

        if x1 == x2:
            return None  # point at infinity

        numerator   = (y2 - y1) % self.p
        denominator = (x2 - x1) % self.p
        lam = (numerator * self.mod_inverse(denominator)) % self.p

        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def point_doubling(self, P):
        """
        Doubles a point P (computes P + P).
        Formula:
          lambda = (3*x1^2 + a) / (2*y1)  mod p
          x3 = lambda^2 - 2*x1             mod p
          y3 = lambda*(x1 - x3) - y1       mod p
        """
        if P is None:
            return None

        x1, y1 = P

        if y1 == 0:
            return None

        numerator   = (3 * x1**2 + self.a) % self.p
        denominator = (2 * y1) % self.p
        lam = (numerator * self.mod_inverse(denominator)) % self.p

        x3 = (lam**2 - 2 * x1) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def scalar_multiply(self, k, P):
        """
        Computes k * P using the double-and-add algorithm.
        Efficient: O(log k) operations instead of O(k).
        """
        result = None   # point at infinity (identity element)
        addend = P

        while k:
            if k & 1:
                result = self.point_addition(result, addend)
            addend = self.point_doubling(addend)
            k >>= 1

        return result


class ECCKeyPair:
    """
    Generates an ECC key pair.
    Private key : d  (secret integer)
    Public key  : Q = d * G  (scalar multiplication)
    """

    def __init__(self, curve, G, private_key):
        self.curve = curve
        self.G = G
        self.private_key = private_key
        self.public_key = curve.scalar_multiply(private_key, G)


class ECElGamal:
    """
    Simplified EC-ElGamal encryption and decryption.

    Encryption of message m:
      C1 = r * G
      C2 = M + r * Q    (M = message encoded as curve point)

    Decryption:
      S  = d * C1  =  r * Q
      M  = C2 - S
    """

    def __init__(self, curve, G, key_pair):
        self.curve = curve
        self.G = G
        self.key_pair = key_pair

    def encode_message(self, m):
        """Encode integer m as a point on the curve."""
        for y in range(self.curve.p):
            point = (m % self.curve.p, y)
            if self.curve.is_on_curve(point):
                return point
        raise ValueError(f"Cannot encode message {m} as a curve point.")

    def decode_message(self, point):
        """Decode a curve point back to its x-coordinate."""
        return point[0]

    def negate_point(self, P):
        """Returns -(x, y) = (x, -y mod p)."""
        if P is None:
            return None
        x, y = P
        return (x, (-y) % self.curve.p)

    def encrypt(self, m, r):
        """
        Encrypts message m with ephemeral key r.
        Returns ciphertext (C1, C2) and encoded point M.
        """
        M  = self.encode_message(m)
        Q  = self.key_pair.public_key
        C1 = self.curve.scalar_multiply(r, self.G)
        rQ = self.curve.scalar_multiply(r, Q)
        C2 = self.curve.point_addition(M, rQ)
        return C1, C2, M

    def decrypt(self, C1, C2):
        """
        Decrypts ciphertext (C1, C2) using private key d.
        Recovers M = C2 - d*C1.
        """
        d     = self.key_pair.private_key
        S     = self.curve.scalar_multiply(d, C1)
        neg_S = self.negate_point(S)
        M     = self.curve.point_addition(C2, neg_S)
        return self.decode_message(M), M


# ── Run ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "#"*60)
    print("#      TASK 2: ELLIPTIC CURVE CRYPTOGRAPHY (ECC)        #")
    print("#"*60)

    # Curve: y^2 = x^3 + 2x + 2  over F_17
    a, b, p = 2, 2, 17
    curve = EllipticCurve(a, b, p)
    G = (5, 1)

    print(f"\n--- Curve Parameters ---")
    print(f"  Equation : y^2 = x^3 + {a}x + {b}  (mod {p})")
    print(f"  Generator: G = {G}")
    print(f"  G on curve: {curve.is_on_curve(G)}")

    # Point Addition
    print(f"\n--- Point Addition ---")
    P = (5, 1)
    Q_pt = (6, 3)
    print(f"  P = {P}   on curve: {curve.is_on_curve(P)}")
    print(f"  Q = {Q_pt}   on curve: {curve.is_on_curve(Q_pt)}")
    R = curve.point_addition(P, Q_pt)
    print(f"  P + Q = {R}   on curve: {curve.is_on_curve(R)}")

    # Point Doubling
    print(f"\n--- Point Doubling ---")
    P2 = curve.point_doubling(P)
    print(f"  2P = 2 * {P} = {P2}   on curve: {curve.is_on_curve(P2)}")

    # Key Generation
    print(f"\n--- Key Generation ---")
    private_key = 7
    keys = ECCKeyPair(curve, G, private_key)
    print(f"  Private Key (d) : {keys.private_key}  (kept secret)")
    print(f"  Public Key  (Q) : {keys.public_key}  (Q = d * G = {private_key} * {G})")
    print(f"  Q on curve      : {curve.is_on_curve(keys.public_key)}")

    # EC-ElGamal Encryption & Decryption
    print(f"\n--- EC-ElGamal Encryption & Decryption ---")
    ecc = ECElGamal(curve, G, keys)

    message = 5
    r = 3

    print(f"\n  Original Message (m) : {message}")
    print(f"  Ephemeral Key    (r) : {r}")

    C1, C2, M_point = ecc.encrypt(message, r)
    print(f"\n  Encoded Point    (M) : {M_point}")
    print(f"  Ciphertext C1 = r*G  : {C1}")
    print(f"  Ciphertext C2 = M+rQ : {C2}")

    decrypted_m, M_recovered = ecc.decrypt(C1, C2)
    print(f"\n  Decrypted Point      : {M_recovered}")
    print(f"  Decrypted Message    : {decrypted_m}")
    print(f"\n  Success: {decrypted_m == message}  —  Original '{message}' matches decrypted '{decrypted_m}'")
