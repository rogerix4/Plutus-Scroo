# Plutus Bitcoin Brute Forcer
# Made by Isaac Delly
# https://github.com/Isaacdelly/Plutus

import os
import pickle
import hashlib
import binascii
import multiprocessing
from pymemcache.client import base
from ellipticcurve.privateKey import PrivateKey

DATABASE_PATH = r'database/MAR_15_2021/'
client = base.Client(('localhost', 11211))


def generate_private_key():
    """
    Generate a random 32-byte hex integer which serves as a randomly 
    generated Bitcoin private key.
    Average Time: 0.0000061659 seconds
    """
    return binascii.hexlify(os.urandom(32)).decode('utf-8').upper()


def private_key_to_public_key(private_key):
    """
    Accept a hex private key and convert it to its respective public key. 
    Because converting a private key to a public key requires SECP256k1 ECDSA 
    signing, this function is the most time consuming and is a bottleneck in 
    the overall speed of the program.
    Average Time: 0.0031567731 seconds
    """
    pk = PrivateKey().fromString(bytes.fromhex(private_key))
    return '04' + pk.publicKey().toString().encode().hex().upper()


def public_key_to_address(public_key):
    """
    Accept a public key and convert it to its resepective P2PKH wallet address.
    Average Time: 0.0000801390 seconds
    """
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count):
        output.append(alphabet[0])
    return ''.join(output[::-1])

def process(private_key, public_key, address):
    """
    Accept an address and query the database. If the address is found in the 
    database, then it is assumed to have a balance and the wallet data is 
    written to the hard drive. If the address is not in the database, then it 
    is assumed to be empty and printed to the user.
    Average Time: 0.0000026941 seconds
    """
    if client.get(str(address)) == b'1': 
        with open('plutus.txt', 'a') as file:
            file.write('hex private key: ' + str(private_key) + '\n' +
                       'WIF private key: ' + str(private_key_to_WIF(private_key)) + '\n' +
                       'public key: ' + str(public_key) + '\n' +
                       'address: ' + str(address) + '\n\n')
        print("!!!! GOT ONE !!!!")
    #else:
        #print(str(address))

def private_key_to_WIF(private_key):
    """
    Convert the hex private key into Wallet Import Format for easier wallet 
    importing. This function is only called if a wallet with a balance is 
    found. Because that event is rare, this function is not significant to the 
    main pipeline of the program and is not timed.
    """
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]):
        value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0:
            pad += 1
        else:
            break
    return chars[0] * pad + result


def main():
    """
    Create the main pipeline by using an infinite loop to repeatedly call the 
    functions, while utilizing multiprocessing from __main__. Because all the 
    functions are relatively fast, it is better to combine them all into 
    one process.
    """
    sanity_check = 1000000
    while True:
        private_key = generate_private_key()			# 0.0000061659 seconds
        public_key = private_key_to_public_key(
            private_key) 	# 0.0031567731 seconds
        address = public_key_to_address(public_key)		# 0.0000801390 seconds
        process(private_key, public_key, address) 	# 0.0000026941 seconds
        if sanity_check > 999999:
            address = '1Ca72914TemMMuDpAscEMeZV3494sztc81'
            if client.get(str(address)) == b'1': 
                print("PROC sanity check pass")
                sanity_check = 0
            else:
                print("PROC check failed")
                quit()
        sanity_check = sanity_check + 1
        # --------------------
        # 0.0032457721 seconds


if __name__ == '__main__':
    """
    Deserialize the database and read into a list of sets for easier selection 
    and O(1) complexity. Initialize the multiprocessing to target the main 
    function with cpu_count() concurrent processes.
    """
    max_processes = multiprocessing.cpu_count()
    print("available threads: " + str(max_processes))
    print("connect memcached...")
    #database = [set() for _ in range(1)]
    database = set()
    count = len(os.listdir(DATABASE_PATH))
    for c, p in enumerate(os.listdir(DATABASE_PATH)):
        print('\rreading database: ' + str(c + 1) + '/' + str(count), end=' ')
        with open(DATABASE_PATH + p, 'rb') as file:
            database = set(pickle.load(file))
        for i in database:
            client.set(i, 1, expire=0)
    print('DONE LOADING DATABASE')
    address = '1Ca72914TemMMuDpAscEMeZV3494sztc81'
    if client.get(str(address)) == b'1': 
        print("sanity check pass")
    else:
        print("check failed")
        quit()

    cpu = 0
    while cpu < max_processes:
        print("thread spawned: " + str(cpu))
        cpu = cpu + 1
        multiprocessing.Process(target=main).start()
