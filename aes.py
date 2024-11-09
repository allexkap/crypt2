class GF28(int):
    base = 2
    degree = 8
    order = 256
    poly = 0b100011011

    def __new__(cls, x: int) -> 'GF28':
        return super().__new__(cls, x % cls.order)

    def __xor__(self, rhs: int) -> 'GF28':
        return GF28(super().__xor__(rhs))

    def __add__(self, rhs: int) -> 'GF28':
        return self ^ rhs

    def __sub__(self, rhs: int) -> 'GF28':
        return self ^ rhs

    def __mul__(self, rhs: int) -> 'GF28':
        result = 0
        for i in range(self.degree):
            if rhs & 1 << i:
                result ^= self << i
        for i in range(self.degree - 1, -1, -1):
            if result & 1 << i + self.degree:
                result ^= self.poly << i
        return GF28(result)

    def __pow__(self, degree: int) -> 'GF28':
        degree %= self.order - 1
        if degree == 0:
            return GF28(1)
        if degree == 1:
            return self
        half = self ** (degree // 2)
        return half * half * self if degree % 2 else half * half

    def __rxor__(self, lhs: int) -> 'GF28':
        return self ^ lhs

    def __radd__(self, lhs: int) -> 'GF28':
        return self + lhs

    def __rsub__(self, lhs: int) -> 'GF28':
        return self - lhs

    def __rmul__(self, lhs: int) -> 'GF28':
        return self * lhs


Block = list[list]


def transpose(block: Block) -> Block:
    return list(map(list, zip(*block)))


def row_shift(row: list, n=1) -> list:
    return row[n:] + row[:n]


def row_sub(row: list, box: list) -> list:
    return [box[a] for a in row]


def row_xor(Arow: list, Brow: list) -> list:
    return [a ^ b for a, b in zip(Arow, Brow)]


def matrix_mul(Am: Block, Bm: Block) -> Block:
    return [[sum(a * b for a, b in zip(Ar, Bc)) for Bc in zip(*Bm)] for Ar in Am]


def to_block(data: bytes, n=4) -> Block:
    return [list(data[i * n : (i + 1) * n]) for i in range(len(data) // n)]


def shift_rows(block: Block, inv=False) -> Block:
    assert len(block[0]) in (4, 6)
    sign = (-1) ** inv
    return [row_shift(row, sign * i) for i, row in enumerate(block)]


def calc_s_item(s: int) -> GF28:
    inv_s = GF28(s) ** -1
    mul_res = sum(
        (sum((inv_s >> ((j + i) % 8)) for j in (0, 4, 5, 6, 7)) & 1) << i
        for i in range(8)
    )
    return GF28(mul_res ^ 0x63)


S_BOX = [calc_s_item(s) for s in range(256)]
INV_S_BOX = list(map(lambda x: x[1], sorted(zip(S_BOX, sorted(S_BOX)))))
MIX_COLUMNS_MATRIX = shift_rows([list(map(GF28, (3, 1, 1, 2)))] * 4)[::-1]
INV_MIX_COLUMNS_MATRIX = shift_rows([list(map(GF28, (11, 13, 9, 14)))] * 4)[::-1]


def sub_bytes(block: Block, inv=False) -> Block:
    box = INV_S_BOX if inv else S_BOX
    return [row_sub(row, box) for row in block]


def mix_columns(block: Block, inv=False) -> Block:
    MATRIX = INV_MIX_COLUMNS_MATRIX if inv else MIX_COLUMNS_MATRIX
    return matrix_mul(MATRIX, block)


def add_round_key(block: Block, round_key: Block) -> Block:
    return [row_xor(Br, Kr) for Br, Kr in zip(block, round_key)]


def aes_block(block_b: bytes, round_keys: list[Block], decrypt=False) -> bytes:
    block = transpose(to_block(block_b))
    rounds = len(round_keys) - 1

    block = add_round_key(block, round_keys[0])
    for i in range(rounds):
        block = sub_bytes(block, decrypt)
        block = shift_rows(block, decrypt)
        if decrypt:
            block = add_round_key(block, round_keys[i + 1])
        if i != rounds - 1:
            block = mix_columns(block, decrypt)
        if not decrypt:
            block = add_round_key(block, round_keys[i + 1])

    block_b = b''.join(map(bytes, transpose(block)))
    return block_b


def key_expansion(key: int):
    round_key = to_block(key.to_bytes(16))

    yield transpose(round_key)
    for i in range(10):
        round_key[0] = row_xor(round_key[0], row_sub(row_shift(round_key[-1]), S_BOX))
        round_key[0][0] ^= GF28(2) ** i
        for j in range(1, 4):
            round_key[j] = row_xor(round_key[j - 1], round_key[j])
        yield transpose(round_key)


def aes(data: bytes, key: int, decrypt=False) -> bytes:
    n = len(data) // 16 + (0 if decrypt else 1)
    blocks = [data[i * 16 : (i + 1) * 16] for i in range(n)]
    if not decrypt:
        padding_size = 16 - len(blocks[-1])
        blocks[-1] += padding_size.to_bytes() * padding_size
    round_keys = list(key_expansion(key))[:: (-1) ** decrypt]
    blocks = [aes_block(block, round_keys, decrypt) for block in blocks]
    if decrypt:
        blocks[-1] = blocks[-1][: -blocks[-1][-1]]
    return b''.join(blocks)
