## Algorithms
1. [Enigma](enigma.py)
1. [DES](des.py)
1. [AES](aes.py)
1. [ECDSA](ecdsa.py)
1. [SHA3](sha3.py)

## Params used in [main.py](main.py)
### Enigma
- Model: **Enigma I**
- Reflector: **UKW A**
- | Rotor | Position | Ring |
  |:-----:|:--------:|:----:|
  |   II  |    1 A   | 24 X |
  |   I   |    2 B   | 13 M |
  |  III  |   12 L   | 22 V |
- Plugboard = `AM FI NV PS TU WZ`

### DES
- Mode: **ECB**
- Padding: **Pkcs7**
- Key:
  - Type: **Hex**
  - Data = `133457799BBCDFF1`

### AES
- Key Size: **128 Bits**
- Mode: **ECB**
- Padding: **Pkcs7**
- Key:
  - Type: **Hex**
  - Data = `00000000000000000000000000000000`

### ECDSA
- Curve: **secp256k1**
- Signature Algorithm: **SHA3 256**
- Public Key:
  - Type: **Hex**
  - Format: **SEC (compressed)**
- Signature:
  - Type: **Hex**
  - Format: **DER**

## Enigma realtime mode
Run `python enigma_demo.py --verbose` and type any text, `llxkp` for example:
```
L -> L -> O -> Q -> K -> W -> P -> L -> P -> S
L -> L -> P -> W -> B -> J -> L -> F -> S -> P
X -> X -> P -> W -> B -> J -> L -> F -> V -> N
K -> K -> P -> W -> B -> J -> L -> F -> S -> P
P -> S -> S -> B -> P -> U -> F -> C -> P -> S
```
