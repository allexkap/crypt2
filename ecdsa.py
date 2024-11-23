import secrets


class Point:
    def __init__(self, x: int, y: int, curve: 'Curve') -> None:
        self.x = x % curve.p
        self.y = y % curve.p
        self.curve = curve
        if (y**2) % curve.p != (x**3 + curve.a * x + curve.b) % curve.p:
            raise ValueError('The point is not on the curve')

    def __neg__(self) -> 'Point':
        return self.curve(self.x, -self.y)

    def __add__(self, rhs: 'Point') -> 'Point':
        if self == rhs and self.y:
            a = 3 * self.x**2 + self.curve.a
            b = 2 * self.y
        elif self.x != rhs.x:
            a = rhs.y - self.y
            b = rhs.x - self.x
        else:
            raise NotImplementedError

        p = self.curve.p
        slope = a % p * pow(b % p, -1, p) % p
        x = slope**2 - self.x - rhs.x
        y = slope * (self.x - x) - self.y
        return self.curve(x, y)

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
        return f'({self.x}, {self.y})'


class Curve:
    def __init__(self, a: int, b: int, p: int) -> None:
        self.a = a
        self.b = b
        self.p = p

    def __call__(self, x: int, y: int) -> Point:
        return Point(x, y, self)

    def from_compressed_form(self, key: str) -> Point:
        x = int.from_bytes(bytes.fromhex(key[2:]))
        y = pow(x**3 + self.a * x + self.b, (self.p + 1) // 4, self.p)
        if y % 2 != ('02', '04').index(key[:2]):
            y = self.p - y
        return self(x, y)


secp256k1 = (
    Curve(
        a=0x0000000000000000000000000000000000000000000000000000000000000000,
        b=0x0000000000000000000000000000000000000000000000000000000000000007,
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    )(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def ecdsa_keygen(
    private_key: int | None = None, domain_params=secp256k1
) -> tuple[int, tuple[int, int]]:
    g_point, n = domain_params

    if private_key is None:
        private_key = secrets.randbelow(n - 1) + 1
    public_key = g_point * private_key

    return private_key, (public_key.x, public_key.y)


def ecdsa_sign(msg: int, private_key: int, domain_params=secp256k1) -> tuple[int, int]:
    g_point, n = domain_params

    k = secrets.randbelow(n - 1) + 1
    r_point = g_point * k
    r = r_point.x % n

    s = ((msg + r * private_key) * pow(k, -1, n)) % n
    assert r != 0 and s != 0, 'ne povezlo'
    return r, s


def ecdsa_verify(
    msg: int,
    sign: tuple[int, int],
    public_key: tuple[int, int],
    domain_params=secp256k1,
) -> bool:
    g_point, n = domain_params
    public_key_point = g_point.curve(*public_key)
    r, s = sign

    inv_s = pow(s, -1, n)
    u = (msg * inv_s) % n
    v = (r * inv_s) % n
    c_point = (g_point * u) + (public_key_point * v)
    return c_point.x == r
