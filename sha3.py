from functools import reduce
from operator import xor


def rol64(a: int, n: int) -> int:
    return (a >> 64 - n % 64) | (a << n % 64) % (1 << 64)


def keccakF1600(state: bytearray) -> bytearray:
    lanes = [
        [int.from_bytes(state[8 * (x + 5 * y) : 8 * (x + 5 * y) + 8]) for y in range(5)]
        for x in range(5)
    ]

    R = 1
    for _ in range(24):
        # θ
        C = [reduce(xor, lanes[x]) for x in range(5)]
        D = [C[(x - 1) % 5] ^ rol64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= D[x]

        # ρ and π
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2 * x + 3 * y) % 5)
            (current, lanes[x][y]) = (
                lanes[x][y],
                rol64(current, (t + 1) * (t + 2) // 2),
            )

        # χ
        for y in range(5):
            T = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = T[x] ^ (~T[(x + 1) % 5] & T[(x + 2) % 5])

        # ι
        for j in range(7):
            R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256
            if R & 2:
                lanes[0][0] ^= 1 << (1 << j) - 1

    state = bytearray().join(
        [lanes[x][y].to_bytes(8) for y in range(5) for x in range(5)]
    )
    return state


def keccak(
    data: bytes,
    rate: int,
    capacity: int,
    delimited_suffix: int,
    output_byte_len: int,
) -> bytes:
    if rate + capacity != 1600 or rate % 8 != 0:
        raise ValueError

    rate_in_bytes = rate // 8
    state = bytearray(200)

    block_size = 0
    for i in range(-(-len(data) // rate_in_bytes)):
        block = data[i * rate_in_bytes : (i + 1) * rate_in_bytes]
        block_size = len(block)
        state[:block_size] = [a ^ b for a, b in zip(state, block)]
        if block_size == rate_in_bytes:
            state = keccakF1600(state)
            block_size = 0

    state[block_size] ^= delimited_suffix
    assert not delimited_suffix & 0x80
    state[rate_in_bytes - 1] ^= 0x80

    return b''.join(
        (state := keccakF1600(state))[:rate_in_bytes]
        for _ in range(-(-output_byte_len // rate_in_bytes))
    )[:output_byte_len]


def sha3_224(data: bytes) -> bytes:
    return keccak(data, 1152, 448, 0x06, 28)


def sha3_256(data: bytes) -> bytes:
    return keccak(data, 1088, 512, 0x06, 32)


def sha3_384(data: bytes) -> bytes:
    return keccak(data, 832, 768, 0x06, 48)


def sha3_512(data: bytes) -> bytes:
    return keccak(data, 576, 1024, 0x06, 64)


def shake128(data: bytes, output_byte_len: int) -> bytes:
    return keccak(data, 1344, 256, 0x1F, output_byte_len)


def shake256(data: bytes, output_byte_len: int) -> bytes:
    return keccak(data, 1088, 512, 0x1F, output_byte_len)
