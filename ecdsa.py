import random

secp256k1_params = {
    'curve': {
        'a': 0x0000000000000000000000000000000000000000000000000000000000000000,
        'b': 0x0000000000000000000000000000000000000000000000000000000000000007,
        'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    },
    'G': {
        'x': 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        'y': 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    },
    'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
}


class Point:
    def __init__(self, x: int, y: int, curve: 'Curve', is_inf=False) -> None:
        self.x = x % curve.p
        self.y = y % curve.p
        self.curve = curve
        self.is_inf = is_inf
        if not is_inf and (y**2) % curve.p != (x**3 + curve.a * x + curve.b) % curve.p:
            raise ValueError('The point is not on the curve')

    def __neg__(self) -> 'Point':
        return Point(self.x, -self.y, self.curve, self.is_inf)

    def __add__(self, rhs: 'Point') -> 'Point':
        if self.is_inf:
            return rhs
        if rhs.is_inf:
            return self

        if self == rhs and self.y:
            a = 3 * self.x**2 + self.curve.a
            b = 2 * self.y
        elif self.x != rhs.x:
            a = rhs.y - self.y
            b = rhs.x - self.x
        else:
            return Point(0, 0, self.curve, True)

        p = self.curve.p
        slope = a % p * pow(b % p, -1, p) % p
        x = slope**2 - self.x - rhs.x
        y = slope * (self.x - x) - self.y
        return Point(x, y, self.curve)

    def __sub__(self, rhs: 'Point') -> 'Point':
        return self + (-rhs)

    def __mul__(self, n: int) -> 'Point':
        if n <= 0:
            raise NotImplementedError
        if n == 1:
            return self
        half = self * (n // 2)
        return half + half + self if n % 2 else half + half

    def __str__(self) -> str:
        return '(inf)' if self.is_inf else f'({self.x}, {self.y})'


class Curve:
    def __init__(self, a: int, b: int, p: int) -> None:
        self.a = a
        self.b = b
        self.p = p

    def __call__(self, x: int, y: int) -> Point:
        return Point(x, y, self)


def ecdsa_keygen(private_key: int | None = None) -> tuple[int, tuple[int, int]]:
    curve = Curve(**secp256k1_params['curve'])
    g_point = curve(**secp256k1_params['G'])
    n = secp256k1_params['n']

    if private_key is None:
        private_key = random.randint(1, n - 1)
    public_key = g_point * private_key

    return private_key, (public_key.x, public_key.y)


def ecdsa_sign(msg: int, private_key: int) -> tuple[int, int]:
    curve = Curve(**secp256k1_params['curve'])
    g_point = curve(**secp256k1_params['G'])
    n = secp256k1_params['n']

    k = random.randint(1, n - 1)
    r_point = g_point * k
    r = r_point.x % n
    assert r != 0, 'ne povezlo'

    s = ((msg + r * private_key) * pow(k, -1, n)) % n
    return r, s


def ecdsa_verify(msg: int, sign: tuple[int, int], public_key: tuple[int, int]) -> bool:
    curve = Curve(**secp256k1_params['curve'])
    g_point = curve(**secp256k1_params['G'])
    public_key_point = curve(*public_key)
    n = secp256k1_params['n']
    r, s = sign

    inv_s = pow(s, -1, n)
    u = (msg * inv_s) % n
    v = (r * inv_s) % n
    c_point = (g_point * u) + (public_key_point * v)
    return c_point.x == r
