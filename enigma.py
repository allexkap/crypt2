WIRING = {
    'I': b'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
    'II': b'AJDKSIRUXBLHWTMCQGZNPYFVOE',
    'III': b'BDFHJLCPRTXVZNYEIWGAKMUSQO',
    'IV': b'ESOVPZJAYQUIRHXLNFTGKDCMWB',
    'V': b'VZBRGITYUPSDNHLXAWMJQOFECK',
    'UKW-A': b'EJMZALYXVBWFCRQUONTSPIKHGD',
    'UKW-B': b'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'UKW-C': b'FVPJIAOYEDRZXWGCTKUQSBNMHL',
    'ETW': b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}
NOTCH = {'I': 'Q', 'II': 'E', 'III': 'V', 'IV': 'J', 'V': 'Z'}
ORD_A = ord('A')


def char2pos(char: str) -> int:
    return ord(char) - ORD_A


def wiring2perm(name: str) -> tuple[int, ...]:
    return tuple(ch - ORD_A - i for i, ch in enumerate(WIRING[name]))


def steckerverbindungen2perm(pairs: list[str]) -> tuple[int, ...]:
    perm = [0] * 26
    for pair in pairs:
        a, b = map(char2pos, pair)
        perm[a] = b - a
        perm[b] = a - b
    return tuple(perm)


class Rotor:
    def __init__(self, perm: tuple[int, ...], notch: int, ring: int, pos: int) -> None:
        self.size = len(perm)
        self.perm = perm
        self.rev_perm = tuple(
            map(
                lambda x: x[1],
                sorted(map(lambda x: (sum(x), -x[1]), enumerate(perm))),
            )
        )
        self.notch = notch
        self.ring = ring
        self.pos = pos

    def rotate(self) -> bool:
        is_advanced = self.pos == self.notch
        self.pos = (self.pos + 1) % self.size
        return is_advanced

    def transmute(self, pin: int, reverse: bool = False) -> int:
        perm = self.rev_perm if reverse else self.perm
        return (pin + perm[(pin + self.pos - self.ring) % self.size]) % self.size


class Enigma:
    def __init__(
        self,
        reflector: str,
        rotors: list[str],
        rings: list[str],
        positions: list[str],
        plugboard: list[str],
    ) -> None:
        self.rotors = [
            Rotor(wiring2perm(w), char2pos(NOTCH[w]), char2pos(r), char2pos(p))
            for w, r, p in zip(rotors, rings, positions)
        ]
        self.reflector = Rotor(wiring2perm(reflector), 0, 0, 0)
        self.plugboard = Rotor(steckerverbindungen2perm(plugboard), 0, 0, 0)
        self.alphabet = set(WIRING['ETW'])

    def rotate(self) -> None:
        for rotor in reversed(self.rotors):
            if not rotor.rotate():
                break

    def round(self, pos: int) -> int:
        self.rotate()
        pos = self.plugboard.transmute(pos)
        for rotor in reversed(self.rotors):
            pos = rotor.transmute(pos)
        pos = self.reflector.transmute(pos)
        for rotor in self.rotors:
            pos = rotor.transmute(pos, reverse=True)
        pos = self.plugboard.transmute(pos)
        return pos

    def transmute_text(self, text: str) -> str:
        return bytes(
            self.round(ch - ORD_A) + ORD_A if ch in self.alphabet else ch
            for ch in text.encode()
        ).decode()
