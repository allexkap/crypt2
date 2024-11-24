from hashlib import sha256

from aes import aes
from des import des
from ecdsa import ecdsa_keygen, ecdsa_sign, ecdsa_verify
from enigma import Enigma

text = open('lorem.txt').read().strip()
print('Text:', repr(text))

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
assert dec_text == src_text
print('\nEnigma:', repr(enc_text.lower()))

src_data = text.encode()
enc_data = des(src_data, 0x133457799BBCDFF1)
dec_data = des(enc_data, 0x133457799BBCDFF1, True)
assert src_data == dec_data
print('\nDES:', enc_data.hex())

src_data = text.encode()
enc_data = aes(src_data, 0)
dec_data = aes(enc_data, 0, True)
assert src_data == dec_data
print('\nAES:', enc_data.hex())

text_hash = int.from_bytes(sha256(text.encode()).digest())
private_key, public_key = ecdsa_keygen()
signature = ecdsa_sign(text_hash, private_key)
assert ecdsa_verify(text_hash, signature, public_key)
print('\nECDSA:')
print(f'{text_hash   = :064x}')
print(f'{private_key = :064x}')
print(f'public_key =  {public_key.hex()}')
print(f'signature =   {signature.hex()}')
