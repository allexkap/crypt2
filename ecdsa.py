import secrets
from dataclasses import dataclass
from typing import Any, Callable


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

    def __eq__(self, rhs: 'Point') -> bool:
        return self.x == rhs.x and self.y == rhs.y and self.curve == rhs.curve

    def __repr__(self) -> str:
        return f'Point(x={self.x}, y={self.y}, curve={repr(self.curve)})'


class Curve:
    def __init__(self, a: int, b: int, p: int) -> None:
        self.a = a
        self.b = b
        self.p = p

    def __call__(self, x: int, y: int) -> Point:
        return Point(x, y, self)

    def __repr__(self) -> str:
        return f'Curve(a={self.a}, b={self.b}, p={self.p})'


@dataclass
class ecdsa_params:
    curve: Curve
    g_point: Point
    n: int
    point_to_str: Callable[[Point], str]
    point_from_str: Callable[[str], Point]


def sec_point_to_str(point: Point, compressed=True) -> str:
    prefix = ('03' if point.y % 2 else '02') if compressed else '04'
    ypart = '' if compressed else f'{point.y:064x}'
    xpart = f'{point.x:064x}'
    return f'{prefix}{xpart}{ypart}'


def sec_point_from_str(text: str) -> Point:
    curve = secp256k1.curve
    prefix = text[:2]
    x = int(text[2:66], 16)
    if prefix == '04':
        y = int(text[66:], 16)
    elif prefix in ('02', '03'):
        y = pow(x**3 + curve.a * x + curve.b, (curve.p + 1) // 4, curve.p)
        if (y % 2) ^ (prefix != '02'):
            y = curve.p - y
    else:
        raise ValueError
    return curve(x, y)


def to_der_format(obj: Any) -> tuple[str, int]:
    match obj:
        case int(value):
            prefix = '02'
            size = -(-value.bit_length() // 8)
            text = f'{value:0{size*2}x}'
        case tuple(items):
            prefix = '30'
            text_parts, sizes = zip(*map(to_der_format, items))
            size = sum(sizes)  # type: ignore
            text = ''.join(text_parts)  # type: ignore
        case obj:
            raise ValueError(f'Unknown type {obj.__class__}')
    return f'{prefix}{size:02x}{text}', size + 2


def parse_der_seq(text: str):
    while text:
        value, size = from_der_format(text)
        text = text[size:]
        yield value


def from_der_format(text: str) -> tuple[Any, int]:
    size = (int(text[2:4], 16) + 2) * 2
    match text[:2]:
        case '02':  # INTEGER
            value = int(text[4:size], 16)
        case '30':  # SEQUENCE
            value = tuple(parse_der_seq(text[4:size]))
        case prefix:
            raise ValueError(f'Unknown type 0x{prefix}')
    return value, size


secp256k1 = ecdsa_params(
    curve := Curve(
        a=0x0000000000000000000000000000000000000000000000000000000000000000,
        b=0x0000000000000000000000000000000000000000000000000000000000000007,
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    ),
    curve(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    sec_point_to_str,
    sec_point_from_str,
)


def ecdsa_keygen(
    private_key: int | None = None,
    params: ecdsa_params = secp256k1,
) -> tuple[int, str]:
    if private_key is None:
        private_key = secrets.randbelow(params.n - 1) + 1
    public_key = params.g_point * private_key

    return private_key, params.point_to_str(public_key)


def ecdsa_sign(
    msg: int,
    private_key: int,
    params: ecdsa_params = secp256k1,
) -> str:
    k = secrets.randbelow(params.n - 1) + 1
    r_point = params.g_point * k
    r = r_point.x % params.n

    s = ((msg + r * private_key) * pow(k, -1, params.n)) % params.n
    assert r != 0 and s != 0, 'ne povezlo'

    return to_der_format((r, s))[0]


def ecdsa_verify(
    msg: int,
    sign: str,
    public_key: str,
    params: ecdsa_params = secp256k1,
) -> bool:
    public_key_point = params.point_from_str(public_key)
    match from_der_format(sign):
        case (int(r), int(s)), l if l == len(sign):
            pass
        case _:
            raise ValueError('Incorrect signature')

    inv_s = pow(s, -1, params.n)
    u = (msg * inv_s) % params.n
    v = (r * inv_s) % params.n
    c_point = (params.g_point * u) + (public_key_point * v)
    return c_point.x == r
