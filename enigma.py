WIRING = {
    'I': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
    'II': 'AJDKSIRUXBLHWTMCQGZNPYFVOE',
    'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
    'IV': 'ESOVPZJAYQUIRHXLNFTGKDCMWB',
    'V': 'VZBRGITYUPSDNHLXAWMJQOFECK',
    'UKW-A': 'EJMZALYXVBWFCRQUONTSPIKHGD',
    'UKW-B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'UKW-C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
    'ETW': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
}
NOTCH = {'I': 'Q', 'II': 'E', 'III': 'V', 'IV': 'J', 'V': 'Z'}
ORD_A = ord('A')


def char2pos(char: str) -> int:
    return ord(char) - ORD_A


def pos2char(pos: int) -> str:
    return chr(pos + ORD_A)


def wiring2perm(name: str) -> tuple[int, ...]:
    return tuple(char2pos(ch) - i for i, ch in enumerate(WIRING[name]))


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
        self.trace = []

    def rotate(self) -> None:
        for rotor in reversed(self.rotors):
            if not rotor.rotate():
                break

    def round(self, char: str) -> str:
        self.rotate()
        self.trace.clear()
        pos = char2pos(char)
        self.trace.append(pos)
        pos = self.plugboard.transmute(pos)
        self.trace.append(pos)
        for rotor in reversed(self.rotors):
            pos = rotor.transmute(pos)
            self.trace.append(pos)
        pos = self.reflector.transmute(pos)
        self.trace.append(pos)
        for rotor in self.rotors:
            pos = rotor.transmute(pos, reverse=True)
            self.trace.append(pos)
        pos = self.plugboard.transmute(pos)
        self.trace.append(pos)
        char = pos2char(pos)
        return char

    def transmute_text(self, text: str) -> str:
        return ''.join(self.round(ch) if ch in self.alphabet else ch for ch in text)

    def get_trace(self):
        return ' -> '.join(map(pos2char, self.trace))
