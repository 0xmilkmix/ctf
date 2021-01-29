# identification

For this challenge, we are provided with two pieces of information:
- an onion link
- a python script, `crypter.py`

Following the link in `Tor Browser`, we access a pseudo-forum with 3 "posts":

```console
Welcome on board!

259F8D014A44C2BE8FC573EAD944BA63 21BB02BE026D599AA43B7AE224E221CF 00098D47F8FFF3A7DBFF21376FF4EB79 B01B8877012536C10394DF7A943731F8 9117B49349E078809EA2EECE4AA86D84 4E94DF7A265574A379EB17E4E1905DB8 49280BD0040C23C98B05F160905DB849 280B6CB9DFECC6C09A0921314BD94ABF 3049280B5BFD8953CA73C8D1F6D0040C 1B967571354BAAB7992339507BBB59C6 5CDA5335A7D575C970F1C9D0040C23C9 8B08F78D3F40B198659B4CB137DEB437 08EB47FB978EF4EB7919BF3E97EA5F40 9F5CF66370141E345024AC7BB966AEDF 5F870F407BB9666F7C4DC85039CBD819 994515C4459F1B96750716906CB9DF34 5106F58B3448E12B87AFE754C0DD802C 41C25C7AAAFF7900B574FC6867EA35C5 BB4E51542C2D0B5645FB9DB1C6D12C8E F62524A12D5D5E622CD443E02515E7EB 991ACCC0C08CE8783F7E2BAD4B16D758 530C79003E5ED61DFE2BE70F50A6F9CA 288C
Let's fight back!

259F8D014A44C2BE8F7FA3BC3656CFB3 DF178DEA8313DBD33A8BAC2CD4432D66 3BC75139ECC6C0FFFBB38FB17F448C08 17BF508074D723AAA722D4239328C6B3 7F57C0A5249EA4E79B780DF081E997C0 6058F702E2BF9F50C4EC1B5966DF27EC 56149F253325CFE57A00B57494692921 94F383A3535024ACA7009088E70E6128 9BD30B2FCFE57A00B5749469292194F3 83A3533BAB08CA7FD9DC778386803149 280BE0895C0984C6DC77838C2085B10B 3ED0040C3759B05029F8085EDBE26DE3 DF25AA87CE0BBBD1169B780D1BCAA097 9A6412CCBE5B68BD2FB780C5DBA34137 C102DBE48D3F0AE471B77387E7FA8BEC 305671785D725930C3E1D05B8BD884C0 A5246EF0BF468E332E0E70009CCCB4C2 ED84137DB4C2EDE078807E1616AA9A7F 4055844821AB16F842
FLAGZ!

259F8D014A44C2BE8FC50A5A2C1EF0C1 3D7F2E0E70009CCCB4C2ED84137DB4C2 EDE078807E1616C266D5A15DC6DDB60E 4B7337E851E739A61EED83D2E06D6184 11DF61222EED83D2E06D612C8EB5294B CD4954E0855F4D71D0F06D05EE
```

# analysis

## forum

Looking at the text we can see that the first 9 characters are the same for the 3 "posts", interesting.

## script

The script requires us to enter 2 arguments and save the 2nd one in a variable `K`. If the length of `K` is not 9, an error is thrown.

```python
len(sys.argv) == 3 or die('FOOL')
K=bytes(sys.argv[2], 'ascii')
len(K)==9 and T(*K)&1 or die('INVALID')
```

`stdin` input is stored in a variable `M` (this starts to look very close to **K**ey and **M**essage...). If the 1st argument is `E` (**E**ncrypt ?), the function `C()` is called with `stdin` input prepended by `SPACEARMY` and `U(K)`. Otherwise, the function `C()` is called with `K` and `M`. In this second case, the first 9 bytes of the function's output is compared to `SPACEARMY`.

```python
if sys.argv[1].upper() == 'E':
    M=B'SPACEARMY'+bytes(M,'ascii')
    print(C(U(K),M).hex().upper())
else:
    M=C(K,bytes.fromhex(M))
    M[:9]==B'SPACEARMY' or die('INVALID')
    print(M[9:].decode('ascii'))
```

Looks like we now know why the 9 first bytes of each paragraph are similar: `SPACEARMY` (9 characters) is always added to the text to encrypt! 

# solution

I went for the decryption function since we can take the first 9 characters of one of the paragraph and we know that the cleartext should be equal to `SPACEARMY`.

Unrolling the optimisations from the `C()` function, we can see a matrix multiplication algorithm (might the challenge title be an hint?!? ;)):

```python
def C(K,M):
    B=lambda A,B,C,D,E,F,G,H,I,X,Y,Z:bytes((A*X+B*Y+C*Z&0xFF,
        D*X+E*Y+F*Z&0xFF,G*X+H*Y+I*Z&0xFF))
    N=len(M)
    R=N%3
    R=R and 3-R
    M=M+R*B'\0'
    return B''.join(B(*K,*W) for W in zip(*[iter(M)]*3)).rstrip(B'\0')
```

I choose to use `z3` (CTO and hipster, but I start to slack on the hipster side, didn't code the solution in `Rust` or `Go`) and came with the following solution:

```python
#!/usr/bin/env python3

from z3 import *

def _chr(x):
	return chr(int(str(x)))

def generate_string(base, length):
    return [BitVec('%s%d' % (base, i), 8) for i in range(length)]

def alpha(c):
    return And(32 <= c, c <= 122)

def print_model(m, var_l):
    found_flag = ''.join(chr(m[x].as_long()) for x in var_l)
    print(f"[+] key : {found_flag} ")

T = lambda A,B,C,D,E,F,G,H,I:A*E*I+B*F*G+C*D*H-G*E*C-H*F*A-I*D*B&255

def C(K, M):
    B=lambda A,B,C,D,E,F,G,H,I,X,Y,Z:bytes((A*X+B*Y+C*Z&0xFF,
        D*X+E*Y+F*Z&0xFF,G*X+H*Y+I*Z&0xFF))

    N=len(M)
    R=N%3
    R=R and 3-R
    M=M+R*B'\0'
    return B''.join(B(*K,*W) for W in zip(*[iter(M)]*3)).rstrip(B'\0')

s = Solver()
key = generate_string('k', 9)
for i in range(0, 8):
    s.add(alpha(key[i]))
s.add(T(*key) & 1 == 1)

M = '259F8D014A44C2BE8FC573EAD944BA63'
M = bytes.fromhex(M)
N= len(M)
R=N % 3
R=R and 3 - R
M=M + R * B'\0'

s.add(((key[0] * M[0] + key[1] * M[1] + key[2] * M[2]) &0xFF) == ord('S'))
s.add(((key[3] * M[0] + key[4] * M[1] + key[5] * M[2]) &0xFF) == ord('P'))
s.add(((key[6] * M[0] + key[7] * M[1] + key[8] * M[2]) &0xFF) == ord('A'))

s.add(((key[0] * M[3] + key[1] * M[4] + key[2] * M[5]) &0xFF) == ord('C'))
s.add(((key[3] * M[3] + key[4] * M[4] + key[5] * M[5]) &0xFF) == ord('E'))
s.add(((key[6] * M[3] + key[7] * M[4] + key[8] * M[5]) &0xFF) == ord('A'))

s.add(((key[0] * M[6] + key[1] * M[7] + key[2] * M[8]) &0xFF) == ord('R'))
s.add(((key[3] * M[6] + key[4] * M[7] + key[5] * M[8]) &0xFF) == ord('M'))
s.add(((key[6] * M[6] + key[7] * M[7] + key[8] * M[8]) &0xFF) == ord('Y'))

if s.check() != unsat:
    while s.check() == sat:
        print_model(s.model(), key)
        exit() 
print(f"[+] no solution can be found")
```

Running it, we have the key a few micro-seconds later:

```console
$ ./sol.py
[+] key : SP4evaCES
```

We can now use it to decypt the forum posts:

```console
$ echo 259F8D014A44C2BE8FC50A5A2C1EF0C13D7F2E0E70009CCCB4C2ED84137DB4C2EDE078807E1616C266D5A15DC6DDB60E4B7337E851E739A61EED83D2E06D618411DF61222EED83D2E06D612C8EB5294BCD4954E0855F4D71D0F06D05EE | ./crypter.py D SP4evaCES
Good job!

040 == 32 == 0x20

CS{if_computers_could_think_would_they_like_spaces?}
```
