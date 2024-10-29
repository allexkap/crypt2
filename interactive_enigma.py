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

fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)
settings = termios.tcgetattr(fd)
settings[3] &= ~(termios.ECHO | termios.ICANON)
try:
    print('> ', end='', flush=True)
    termios.tcsetattr(fd, termios.TCSADRAIN, settings)
    while (ch := sys.stdin.read(1).upper()) != '\x04':
        print(enigma.transmute_text(ch), end='', flush=True)
except KeyboardInterrupt:
    pass
finally:
    print()
    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
