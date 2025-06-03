import json 
import random
import base64
import os
from sympy import isprime

def is_prime(n, k=64):
    """Проверка числа на простоту тестом Миллера-Рабина"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False
    
    # Представляем n-1 в виде (2^s)*d
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Генерация большого простого числа"""
    while True:
        p = random.getrandbits(bits)
        if p % 2 != 0 and isprime(p):
            return p

def extended_gcd(a, b):
    """Расширенный алгоритм Евклида (для нахождения обратного элемента)"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    """Нахождение обратного элемента a^(-1) mod m"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Обратный элемент не существует')
    else:
        return x % m

def generate_rsa_keys(bits=2048):
    """Генерация ключей RSA"""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)  # (public_key, private_key)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def L(x, n):
    return (x - 1) // n  # Целочисленное деление!

def generate_paillier_keys(p, q):
    n = p * q
    lambda_val = lcm(p - 1, q - 1)
    
    return n, lambda_val, 

def ask(prompt, default=None, cast_func=str):
    value = input(f"{prompt} [{default}]: ") or default
    try:
        return cast_func(value)
    except ValueError:
        print("Неверный ввод. Попробуй снова.")
        return ask(prompt, default, cast_func)
    


CONFIG_FILE = "crypto.json"


def load_config():
    """Загрузка конфигурации из файла, если он существует"""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(config):
    """Сохранение конфигурации в файл"""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def generate_config():
    config = load_config()
    voting_id = ask("Введите идентификатор голосования (положительное число)", default=1)

    config[voting_id]={}
    config[voting_id]["voting_id"]=voting_id
    base = int(ask("Каков битовый размер числа для обозначения количества всех голосующих? (кратно 8)", default=24))
    while base%8 != 0:
        base = int(ask("Каков битовый размер числа для обозначения количества всех голосующих? (кратно 8)", default=24))

    config[voting_id]["base"] = base

    config[voting_id]["re_voting_multiplier"] = int(ask("Случайный множитель обозначения переголосования? (2...n)", default=3))
    config[voting_id]["challenge_bits"] = int(ask("Размер челленджа? (2...n)", default=256))
    bits_length = int(ask("Какова битность генерируемых ключей RSA?", default=4096))

    (e, n), (d, n) = generate_rsa_keys(bits=int(bits_length))
    config[voting_id]["rsa"]={}


    config[voting_id]["rsa"]["n"]=base64.b64encode(str(n).encode("utf-8")).decode("utf-8")
    config[voting_id]["rsa"]["d"]=base64.b64encode(str(e).encode("utf-8")).decode("utf-8")
    config[voting_id]["rsa"]["e"]=base64.b64encode(str(d).encode("utf-8")).decode("utf-8")

    bits_length = int(ask("Какова битность генерируемых ключей Paillier?", default=2048))

    n, lambda_ = generate_paillier_keys(generate_prime(bits_length), generate_prime(bits_length))
    config[voting_id]["paillier"]={}
    config[voting_id]["paillier"]["n"] = base64.b64encode(str(n).encode("utf-8")).decode("utf-8")
    config[voting_id]["paillier"]["lambda"]=base64.b64encode(str(lambda_).encode("utf-8")).decode("utf-8")


    save_config(config)
    print(f"✅ Конфигурация для голосования ID={voting_id} сохранена в '{CONFIG_FILE}'.")


if __name__ == "__main__":
    generate_config()







    
