import sys
import termios

from enigma import Enigma

enigma = Enigma(
    reflector='UKW-A',
    rotors=['II', 'I', 'III'],
    rings=['X', 'M', 'V'],
    positions=['A', 'B', 'L'],
    plugboard=['AM', 'FI', 'NV', 'PS', 'TU', 'WZ'],
)

verbose = len(sys.argv) - 1

fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)
settings = termios.tcgetattr(fd)
settings[3] &= ~(termios.ECHO | termios.ICANON)
try:
    termios.tcsetattr(fd, termios.TCSADRAIN, settings)
    while (ch := sys.stdin.read(1).upper()) != '\x04':
        ch = enigma.transmute_text(ch)
        if verbose:
            print(enigma.get_trace())
        else:
            print(ch, end='', flush=True)
except KeyboardInterrupt:
    pass
finally:
    if not verbose:
        print()
    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
