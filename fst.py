#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jan 19 12:49:10 2023

@author: sk
"""


########### test de %timeits ###########################3
from eth_account import Account
import secrets
def uno():
    priv = secrets.token_hex(32)
    private_key = "0x" + priv
    #print ()
    acct = Account.from_key(private_key)
    #print("SAVE BUT DO NOT SHARE THIS:", private_key,"\n","Address:", acct.address)




import multiprocessing as mp

import random
import time
import multiprocessing

from secrets import token_bytes
from coincurve import PublicKey
from Crypto.Hash import keccak


def WalletRandGen(value):
    value = random.randrange(2**256)
    seed = value.to_bytes(32, 'big')
    private_key = seed #keccak.new(data = seed, digest_bits=256).digest()

    # private_key_bytes = str.encode(private_key)

    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak.new(data = public_key, digest_bits=256).digest()[-20:]
    
    #addr_format = '0x' + addr.hex()
    addr_format = addr.hex()
    o = private_key.hex()
    #print(len(addr_format),len(o))

    #return (addr_format, private_key.hex())
    
    
from secrets import token_bytes
from coincurve import PublicKey
from sha3 import keccak_256

def dos():
    private_key = keccak_256(token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    
    private_key = private_key.hex()
    addr = addr.hex()
    #print(len(addr),len(private_key))
    #print('private_key:', private_key)
    #print('eth addr: 0x' + addr)
#############################################################################################




# usando dos() (la mas rapida)
def damePublica(privada):
    private_key = privada
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    addr = keccak_256(public_key).digest()[-20:]
    
    p = private_key.hex()
    a = addr.hex()
    return p, a

a,b = 'aa','a'
def milSec(n=int(1e6)):
    n=int(1e6)
    private_key = keccak_256(token_bytes(32)).digest()
    contador = 0
    for _ in range(n):
        contador += 1
        privada, publica = damePublica(private_key)
        private_key = (int(private_key.hex(),16)+1).to_bytes(32,'big') # optimizable
        if publica[:len(a)] == a and publica[-len(b):] == b:
            #print("encontrada: ", contador)
            return contador, privada, publica
    return False
        
def milRan(n=int(1e6)):
    n=int(1e6)
    contador = 0
    for _ in range(n):
        contador+=1
        private_key = keccak_256(token_bytes(32)).digest()
        privada, publica = damePublica(private_key)
        if publica[:len(a)] == a and publica[-len(b):] == b:
            #print("encontrada: ",contador)
            return contador, privada, publica
    return False
        
import matplotlib.pyplot as plt
import numpy as np


# experimento secuencial vs random
def experimenta(experimentos = 1000):
    secuencial, randomm = [], []
    toS, toR = [], []
    for _ in range(experimentos):
        s = milSec()
        toS.append(s)
        secuencial.append(s[0])
        
        r = milRan()
        toR.append(r)
        randomm.append(r[0])
        
    print("SECUENCIAL, mean:",np.mean(secuencial),", varianza: ",np.std(secuencial))
    plt.hist(secuencial, bins=100)
    plt.show()

    print("RANDOMM, mean:",np.mean(randomm),", varianza: ",np.std(randomm))
    plt.hist(randomm, bins=100)
    plt.show()


#PARALELO
def paralSec():
    pool = mp.Pool(mp.cpu_count())
    res = pool.map(milSec, [i for i in range(mp.cpu_count())])
    #print(res)
    return res

def paralRan():
    pool = mp.Pool(mp.cpu_count())
    res = pool.map(milRan, [i for i in range(mp.cpu_count())])
    #print(res)
    return res


from datetime import datetime
 
def queHoraEs():
    #print(datetime.fromtimestamp(round(datetime.timestamp(datetime.now()))))
    return datetime.fromtimestamp(round(datetime.timestamp(datetime.now())))

# test pal paralelo
cuantas = 5 # quiero 5 claves
def dameNoParalelo(cuantas=5):
    print("empiezas a las: ", queHoraEs())
    resultado = []
    while len(resultado)<cuantas:
        ole = milSec()
        if ole: resultado.append(ole)
    print("NOPARALELO: aki tienes las ", len(resultado))
    print("terminas a las: ", queHoraEs())
    return resultado

def dameParalelo(cuantas=5):
    print("empiezas a las: ", queHoraEs())
    resultado = []
    while len(resultado)<cuantas:
        res = paralRan()
        for ri in res:
            if ri: resultado.append(ri)
    print("PARALELO: aki tienes las ", len(resultado))
    print("terminas a las: ", queHoraEs())
    return resultado
 
#dameNoParalelo(20)
#dameParalelo(20)

"""
DOCUMENTAO


    ## STEP 1: GENERATE A PRIVATE KEY ##
    #----------------------------------#
    # Ethereum private keys are based on KECCAK-256 hashes (https://keccak.team/keccak.html).
    # To generate such a hash we use the `keccak_256` function 
    # from the `pysha3` module on a random 32 byte seed:
    private_key = keccak_256(token_bytes(32)).digest()

    ## STEP 2: DERIVE THE PUBLIC KEY FROM THE PRIVATE KEY ##
    #------------------------------------------------------#
    # To get our public key we need to sign our private key with an
    # Elliptic Curve Digital Signature Algorithm (ECDSA).
    # Ethereum uses the `secp256k1` curve ECDSA. 
    # `coincurve` uses this as a default so we don't need to 
    # explicitly specify it when calling the function:
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]

    # The Ethereum Yellow Paper (https://ethereum.github.io/yellowpaper/paper.pdf)
    # states that the public key has to be a byte array of size 64. By default 
    # `coincurve` uses the compressed format for public keys (`libsecp256k1` 
    # was developed for Bitcoin, where compressed keys are commonly used) 
    # which is 33 bytes in size. Uncompressed keys are 65 bytes in size.
    # Additionally all public keys are prepended with a single byte to indicate
    # if they are compressed or uncompressed. This means we first need to get
    # the uncompressed 65 byte key (`compressed=False`) and then strip the 
    # first byte (`[1:]`) to get our 64 byte Ethereum public key.

    ## STEP 3: DERIVE THE ETHEREUM ADDRESS FROM THE PUBLIC KEY ##
    #-----------------------------------------------------------#
    # As specified in the Ethereum Yellow Paper (https://ethereum.github.io/yellowpaper/paper.pdf)
    # we take the right most 20 bytes of the 32 byte `KECCAK` hash of the 
    # corresponding ECDSA public key.
    addr = keccak_256(public_key).digest()[-20:]

    p = private_key.hex()
    a = addr.hex()
    
    #print('private_key:', private_key.hex())
    #print('eth addr: 0x' + addr.hex())
    



"""