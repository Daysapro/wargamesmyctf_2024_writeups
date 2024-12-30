from pwn import *
from Crypto.Util.number import *
from math import gcd
from tqdm import tqdm
from sympy import integer_nthroot
from sympy.ntheory.modular import crt
import json
import os
import time

context.log_level = "CRITICAL"
SAVE_FILE = "results.json"
MAX_RETRIES = 3


def load_results():
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, "r") as f:
            data = json.load(f)
        return data.get("Ns", []), data.get("cts", [])
    return [], []


def save_results(Ns, cts):
    current_data = set(zip(Ns, cts))
    new_data = list(zip(Ns, cts))
    
    if len(current_data) < len(new_data):
        raise ValueError("Duplicado detectado, lanzando reintento.")
    
    with open(SAVE_FILE, "w") as f:
        json.dump({"Ns": Ns, "cts": cts}, f)


def get_flag(r):
    r.recvuntil(b"Enter option: ")
    r.sendline(b"3")
    r.recvuntil(b"Encrypted flag: ")
    return int(r.recvline().strip())


def encrypt(r, pt):
    r.recvuntil(b"Enter option: ")
    r.sendline(b"1")
    r.recvuntil(b"Enter message to encrypt: ")
    r.sendline(long_to_bytes(pt))
    r.recvuntil(b"Encrypted message: ")
    return int(r.recvline().strip())


def recover_n(e, r):
    two = encrypt(r, 2)
    three = encrypt(r, 3)
    four = encrypt(r, 4)
    nine = encrypt(r, 9)
    n = GCD(GCD(pow(2, e) - two, pow(3, e) - three), GCD(pow(two, 2) - four, pow(three, 2) - nine))
    return n


def worker_task():
    retries = 0
    while retries < MAX_RETRIES:
        try:
            r = remote("43.217.80.203", 34100)
            ct = get_flag(r)
            N = recover_n(e, r)
            return N, ct
        except Exception as ex:
            retries += 1
            print(f"Error en worker_task, reintento {retries}/{MAX_RETRIES}: {ex}")
            time.sleep(1)
    raise RuntimeError(f"worker_task falló después de {MAX_RETRIES} intentos")


Ns, cts = load_results()
e = 0x557

for _ in tqdm(range(e - len(Ns)), desc="Procesando tareas"):
    try:
        N, ct = worker_task()
        
        if (N, ct) in zip(Ns, cts):
            raise ValueError("Par duplicado detectado, reintentando.")
        
        Ns.append(N)
        cts.append(ct)
        save_results(Ns, cts)
    except Exception as ex:
        print(f"Error en el procesamiento de una tarea: {ex}")

M, _ = crt(Ns, cts)
print(integer_nthroot(M, e))