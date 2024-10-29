from des import des
from enigma import Enigma

text = open('lorem.txt').read().strip()

src_data = text.encode()
enc_data = des(src_data, 0x133457799BBCDFF1)
dec_data = des(enc_data, 0x133457799BBCDFF1, True)
print('DES')
print('decrypted == source:', src_data in dec_data)
print('encrypted:', repr(enc_data.hex()))

params = {
    'reflector': 'UKW-A',
    'rotors': ['II', 'I', 'III'],
    'rings': ['X', 'M', 'V'],
    'positions': ['A', 'B', 'L'],
    'plugboard': ['AM', 'FI', 'NV', 'PS', 'TU', 'WZ'],
}
src_text = text.upper()
enc_text = Enigma(**params).transmute_text(src_text)
dec_text = Enigma(**params).transmute_text(enc_text)
print('\nEnigma')
print('decrypted == source:', dec_text == src_text)
print('encrypted:', repr(enc_text.lower()))
