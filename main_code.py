import os
import csv     
import json
import base64
import hashlib
import random
import math
from pathlib import Path
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

# Crypto utilities (same as before)
def egcd(a, b):
    if b == 0: return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1: raise Exception

def is_probable_prime(n, k=8):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    d, s = n - 1, 0
    while d % 2 == 0: d//=2; s+=1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a,d,n)
        if x==1 or x==n-1: continue
        for __ in range(s-1):
            x = pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def generate_prime(nbits=512):
    while True:
        cand = random.getrandbits(nbits) | (1<<(nbits-1)) | 1
        if is_probable_prime(cand): return cand

def generate_rsa_keypair(nbits=1024):
    p, q = generate_prime(nbits//2), generate_prime(nbits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1: e+=2
    d = modinv(e, phi)
    return {'n':n,'e':e,'d':d}

def rsa_encrypt_int(m_int, pub):
    return pow(m_int, pub['e'], pub['n'])

def rsa_decrypt_int(c_int, priv):
    return pow(c_int, priv['d'], priv['n'])

def sha256_stream(key_bytes, length):
    out, counter = bytearray(), 0
    while len(out)<length:
        h = hashlib.sha256(key_bytes + counter.to_bytes(8,'big')).digest()
        out.extend(h)
        counter += 1
    return bytes(out[:length])

def xor_encrypt(plaintext_bytes, key_bytes):
    ks = sha256_stream(key_bytes,len(plaintext_bytes))
    return bytes(a^b for a,b in zip(plaintext_bytes,ks))

def xor_decrypt(cipher_bytes,key_bytes):
    return xor_encrypt(cipher_bytes,key_bytes)

# Shamir 
P = 2**521-1
def shamir_split(secret_int,n,t,prime=P):
    if secret_int>=prime: raise ValueError("Secret too large")
    coeffs = [secret_int]+[random.randrange(0,prime) for _ in range(t-1)]
    def eval_poly(x):
        res,power=0,1
        for c in coeffs:
            res = (res + c*power)%prime
            power=(power*x)%prime
        return res
    return [(i,eval_poly(i)) for i in range(1,n+1)]

def lagrange_interpolate(x,x_s,y_s,p):
    total=0
    k=len(x_s)
    for i in range(k):
        xi,yi=x_s[i],y_s[i]
        num,den=1,1
        for j in range(k):
            if i==j: continue
            xj=x_s[j]
            num=(num*(x-xj))%p
            den=(den*(xi-xj))%p
        inv_den=modinv(den,p)
        total=(p+total+yi*num*inv_den)%p
    return total

def shamir_recover(shares,prime=P):
    x_s=[s[0] for s in shares]
    y_s=[s[1] for s in shares]
    return lagrange_interpolate(0,x_s,y_s,prime)

# File paths
EXCEL_FILE = Path("patients_data_with_alerts.xlsx")
ENCRYPTED_FILE = Path("encrypted_patient_data.csv")


def encrypt_excel(input_path, output_path):
    rsa = generate_rsa_keypair()
    rsa_pub = {'n':rsa['n'],'e':rsa['e']}
    rsa_priv = {'n':rsa['n'],'d':rsa['d']}
    NUM_SHARES, THRESHOLD = 5,3

    df = pd.read_excel(input_path)
    encrypted_rows=[]
    for i,row in df.iterrows():
        row_dict = row.to_dict()
        plaintext = json.dumps(row_dict, separators=(',',':')).encode('utf-8')
        sym_key = random.getrandbits(32*8).to_bytes(32,'big')
        ciphertext = xor_encrypt(plaintext,sym_key)
        key_int = int.from_bytes(sym_key,'big')
        encrypted_key_int = rsa_encrypt_int(key_int,rsa_pub)
        shares = shamir_split(key_int,NUM_SHARES,THRESHOLD)
        encrypted_rows.append({
            'row_id':i+1,
            'EncryptedMessage_b64':base64.b64encode(ciphertext).decode('utf-8'),
            'EncryptedKey_int_b64':base64.b64encode(str(encrypted_key_int).encode()).decode('utf-8'),
            'ShamirShares':json.dumps(shares)
        })

    out_fields=['row_id','EncryptedMessage_b64','EncryptedKey_int_b64','ShamirShares']
    with open(output_path,'w',newline='',encoding='utf-8') as outf:
        writer = csv.DictWriter(outf,fieldnames=out_fields)
        writer.writeheader()
        for r in encrypted_rows: writer.writerow(r)

    print(f"Encrypted CSV written to: {output_path}")
    # Show first 2 rows
    for r in encrypted_rows[:2]:
        print(json.dumps(r,indent=2))

encrypt_excel(EXCEL_FILE, ENCRYPTED_FILE)

import json
import base64
import hashlib
import random
import math
import csv
from pathlib import Path

def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1:
        raise Exception("modinv does not exist")
    return x % m

#(same  as encryption pipeline)
def is_probable_prime(n, k=8):
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    d = n-1
    s = 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(nbits=512):
    while True:
        cand = random.getrandbits(nbits) | (1 << (nbits-1)) | 1
        if is_probable_prime(cand):
            return cand

def generate_rsa_keypair(nbits=1024):
    p = generate_prime(nbits//2)
    q = generate_prime(nbits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d}

def sha256_digest_bytes(data_bytes):
    return hashlib.sha256(data_bytes).digest()

def rsa_sign_bytes(message_bytes, rsa_priv):

    h = sha256_digest_bytes(message_bytes)
    h_int = int.from_bytes(h, 'big')
    # signature = h_int ^ d mod n
    sig_int = pow(h_int, rsa_priv['d'], rsa_priv['n'])
    return sig_int

def rsa_verify_bytes(message_bytes, sig_int, rsa_pub):
    """
    Verify signature: compute SHA256(message)
    """
    h = sha256_digest_bytes(message_bytes)
    h_int = int.from_bytes(h, 'big')
    recovered = pow(sig_int, rsa_pub['e'], rsa_pub['n'])
    return h_int == recovered

# load encrypted CSV, sign first row ciphertext
def shout_print(s):
    print(str(s).upper())

def demo_auth(encrypted_csv_path):
    # 1) Generate RSA keypair 
    rsa = generate_rsa_keypair(nbits=1024)
    rsa_pub = {'n': rsa['n'], 'e': rsa['e']}
    rsa_priv = {'n': rsa['n'], 'd': rsa['d']}

    shout_print("RSA KEYPAIR GENERATED (DEMO)")

    # 2) Read encrypted CSV and extract first EncryptedMessage_b64
    path = Path(encrypted_csv_path)
    if not path.exists():
        shout_print(f"ERROR: ENCRYPTED CSV NOT FOUND AT {encrypted_csv_path}")
        return

    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        first_row = None
        for row in reader:
            first_row = row
            break

    if first_row is None:
        shout_print("ERROR: ENCRYPTED CSV IS EMPTY")
        return

    ciphertext_b64 = first_row.get('EncryptedMessage_b64')
    if not ciphertext_b64:
        shout_print("ERROR: 'ENCRYPTEDMESSAGE_B64' COLUMN NOT FOUND")
        return

    ciphertext_bytes = base64.b64decode(ciphertext_b64)

    # 3) Sign the ciphertext bytes using RSA private key
    signature_int = rsa_sign_bytes(ciphertext_bytes, rsa_priv)

    # 4) Verify signature using public key
    verified = rsa_verify_bytes(ciphertext_bytes, signature_int, rsa_pub)

    # 5) Print (shout) results: signature (hex), verification result, row_id
    shout_print("AUTHENTICATION DEMO OUTPUT:")
    shout_print(f"ROW_ID: {first_row.get('row_id', 'UNKNOWN')}")
    shout_print(f"SIGNATURE (HEX): {hex(signature_int)}")
    shout_print(f"VERIFICATION: {'SUCCESS' if verified else 'FAILURE'}")

    signed_record = {
        'row_id': first_row.get('row_id'),
        'EncryptedMessage_b64': ciphertext_b64,
        'Signature_int_hex': hex(signature_int),
        'SignerPublicKey': {'n': rsa_pub['n'], 'e': rsa_pub['e']}
    }
    shout_print("SIGNED RECORD (JSON):")
    shout_print(json.dumps(signed_record))

if __name__ == "__main__":
    ENCRYPTED_CSV_PATH = "encrypted_patient_data.csv"
    demo_auth(ENCRYPTED_CSV_PATH)

import csv
import json
import base64

# FbRSAEF: Decryption Utilities
def rsa_decrypt_int(c_int, priv):
    return pow(c_int, priv['d'], priv['n'])

def xor_decrypt(cipher_bytes, key_bytes):
    from hashlib import sha256
    def sha256_stream(key_bytes, length):
        out, counter = bytearray(), 0
        while len(out) < length:
            h = sha256(key_bytes + counter.to_bytes(8,'big')).digest()
            out.extend(h)
            counter += 1
        return bytes(out[:length])
    ks = sha256_stream(key_bytes, len(cipher_bytes))
    return bytes(a ^ b for a, b in zip(cipher_bytes, ks))


# Shamir Recovery
from math import gcd

P = 2**521 - 1
def modinv(a, m):
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)
    x, y, g = egcd(a, m)
    if g != 1:
        raise Exception("modinv does not exist")
    return x % m

def lagrange_interpolate(x, x_s, y_s, p):
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num, den = 1, 1
        for j in range(k):
            if i == j: 
                continue
            xj = x_s[j]
            num = (num * (x - xj)) % p
            den = (den * (xi - xj)) % p
        inv_den = modinv(den, p)
        total = (p + total + yi * num * inv_den) % p
    return total

def shamir_recover(shares, prime=P):
    x_s = [s[0] for s in shares]
    y_s = [s[1] for s in shares]
    return lagrange_interpolate(0, x_s, y_s, prime)


# Decrypt CSV File
def decrypt_csv(enc_file, rsa_priv):
    decrypted_rows = []
    with open(enc_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ciphertext = base64.b64decode(row['EncryptedMessage_b64'])
            encrypted_key_int = int(base64.b64decode(row['EncryptedKey_int_b64']).decode())
            shares = json.loads(row['ShamirShares'])

            # Recover symmetric key from Shamir shares
            recovered_key_int = shamir_recover(shares[:3])  # need threshold (3) shares
            sym_key = recovered_key_int.to_bytes(32, 'big')

            # Decrypt
            plaintext_bytes = xor_decrypt(ciphertext, sym_key)
            plaintext = json.loads(plaintext_bytes.decode('utf-8'))

            decrypted_rows.append(plaintext)

    # Print first 2 decrypted rows
    for r in decrypted_rows[:2]:
        print(json.dumps(r, indent=2))

    return decrypted_rows



# Example 
if __name__ == "__main__":
    rsa_priv = {
        "n": 0,  
        "d": 0   
    }

    decrypted_data = decrypt_csv("encrypted_patient_data.csv", rsa_priv)
import os
import csv
import json
import base64
import hashlib
import random
import math
import time
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix

#FbRSAEF Utilities 
def egcd(a, b):
    if b == 0: return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1: raise Exception("modinv does not exist")
    return x % m

def sha256_stream(key_bytes, length):
    out, counter = bytearray(), 0
    while len(out) < length:
        h = hashlib.sha256(key_bytes + counter.to_bytes(8,'big')).digest()
        out.extend(h)
        counter += 1
    return bytes(out[:length])

def xor_encrypt(plaintext_bytes, key_bytes):
    ks = sha256_stream(key_bytes, len(plaintext_bytes))
    return bytes(a ^ b for a, b in zip(plaintext_bytes, ks))

xor_decrypt = xor_encrypt  # symmetric

def rsa_encrypt_int(m_int, pub):
    return pow(m_int, pub['e'], pub['n'])

def rsa_decrypt_int(c_int, priv):
    return pow(c_int, priv['d'], priv['n'])

def generate_prime(nbits=512):
    while True:
        cand = random.getrandbits(nbits) | (1<<(nbits-1)) | 1
        if all(cand % p != 0 for p in [2,3,5,7,11,13,17,19,23,29]):
            return cand

def generate_rsa_keypair(nbits=1024):
    p, q = generate_prime(nbits//2), generate_prime(nbits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1: e+=2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d}

#Shamir Secret Sharing
P = 2**521 - 1

def shamir_split(secret_int, n, t, prime=P):
    if secret_int >= prime: raise ValueError("Secret too large")
    coeffs = [secret_int] + [random.randrange(0, prime) for _ in range(t-1)]
    def eval_poly(x):
        res, power = 0, 1
        for c in coeffs:
            res = (res + c*power) % prime
            power = (power*x) % prime
        return res
    return [(i, eval_poly(i)) for i in range(1, n+1)]

def lagrange_interpolate(x, x_s, y_s, p):
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num, den = 1, 1
        for j in range(k):
            if i==j: continue
            xj = x_s[j]
            num = (num*(x - xj)) % p
            den = (den*(xi - xj)) % p
        inv_den = modinv(den, p)
        total = (p + total + yi*num*inv_den) % p
    return total

def shamir_recover(shares, prime=P):
    x_s = [s[0] for s in shares]
    y_s = [s[1] for s in shares]
    return lagrange_interpolate(0, x_s, y_s, prime)

#File Paths 
EXCEL_FILE = Path("patients_data_with_alerts.xlsx")
ENCRYPTED_FILE = Path("encrypted_patient_data.csv")
ENCRYPTED_FILE.parent.mkdir(parents=True, exist_ok=True)

#Performance Analysis
def shout_print(s):
    print(str(s).upper())

def performance_analysis():
    NUM_SHARES = 5
    THRESHOLD = 3

    df = pd.read_excel(EXCEL_FILE)
    total_rows = len(df)
    rsa = generate_rsa_keypair()

    encrypted_rows = []

    #ENCRYPTION
    start_enc = time.time()
    for i, row in df.iterrows():
        plaintext = json.dumps(row.to_dict(), separators=(',',':')).encode('utf-8')
        sym_key = random.getrandbits(32*8).to_bytes(32,'big')
        ciphertext = xor_encrypt(plaintext, sym_key)
        key_int = int.from_bytes(sym_key,'big')
        encrypted_key_int = rsa_encrypt_int(key_int, rsa)
        shares = shamir_split(key_int, NUM_SHARES, THRESHOLD)
        encrypted_rows.append({
            'row_id': i+1,
            'EncryptedMessage_b64': base64.b64encode(ciphertext).decode('utf-8'),
            'EncryptedKey_int_b64': base64.b64encode(str(encrypted_key_int).encode()).decode('utf-8'),
            'ShamirShares': json.dumps(shares)
        })
    end_enc = time.time()
    encryption_time = end_enc - start_enc

    # Save encrypted CSV
    out_fields = ['row_id','EncryptedMessage_b64','EncryptedKey_int_b64','ShamirShares']
    with open(ENCRYPTED_FILE,'w',newline='',encoding='utf-8') as outf:
        writer = csv.DictWriter(outf, fieldnames=out_fields)
        writer.writeheader()
        for r in encrypted_rows: writer.writerow(r)

    # ----- DECRYPTION -----
    start_dec = time.time()
    decrypted_rows = []
    for r in encrypted_rows:
        ciphertext = base64.b64decode(r['EncryptedMessage_b64'])
        shares = json.loads(r['ShamirShares'])
        recovered_key_int = shamir_recover(shares[:THRESHOLD])
        sym_key = recovered_key_int.to_bytes(32,'big')
        plaintext_bytes = xor_decrypt(ciphertext, sym_key)
        decrypted_rows.append(json.loads(plaintext_bytes.decode('utf-8')))
    end_dec = time.time()
    decryption_time = end_dec - start_dec

    #PERFORMANCE METRICS 
    total_time = encryption_time + decryption_time
    shout_print("PERFORMANCE ANALYSIS (FbRSAEF)")
    shout_print(f"TOTAL ROWS: {total_rows}")
    shout_print(f"ENCRYPTION TIME (SEC): {encryption_time:.4f}")
    shout_print(f"DECRYPTION TIME (SEC): {decryption_time:.4f}")
    shout_print(f"TOTAL LATENCY PER ROW (SEC): {total_time/total_rows:.6f}")
    shout_print(f"THROUGHPUT (ROWS/SEC): {total_rows/total_time:.2f}")
    shout_print(f"BANDWIDTH (BYTES): {ENCRYPTED_FILE.stat().st_size}")
    # Accuracy
    correct = sum(1 for a,b in zip(df.to_dict(orient='records'), decrypted_rows) if a==b)
    accuracy = correct/total_rows*100
    shout_print(f"ACCURACY (%): {accuracy:.2f}")
    
    from sklearn.metrics import precision_score, recall_score, f1_score

    # PRECISION, RECALL, F1 CALCULATION
    original_records = [
        json.dumps(r, sort_keys=True)
        for r in df.to_dict(orient='records')
    ]

    decrypted_records = [
        json.dumps(r, sort_keys=True)
        for r in decrypted_rows
    ]

    y_true = [1] * len(original_records)

    y_pred = [
        1 if a == b else 0
        for a, b in zip(original_records, decrypted_records)
    ]

    precision = precision_score(
        y_true,
        y_pred,
        average='binary',
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        average='binary',
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        average='binary',
        zero_division=0
    )

    shout_print(f"PRECISION (%): {precision*100:.2f}")
    shout_print(f"RECALL (%): {recall*100:.2f}")
    shout_print(f"F1-SCORE (%): {f1*100:.2f}")

    # PRECISION GRAPH
    plt.figure(figsize=(6,4))
    plt.bar(['Precision'], [precision * 100])
    plt.title('Precision (%)')
    plt.ylabel('Percentage (%)')

    for i, v in enumerate([precision * 100]):
        plt.text(i, v + 0.5, f'{v:.2f}%')

    plt.ylim(0, 105)
    plt.grid(True)
    plt.show()

    # RECALL GRAPH
    plt.figure(figsize=(6,4))
    plt.bar(['Recall'], [recall * 100])
    plt.title('Recall (%)')
    plt.ylabel('Percentage (%)')

    for i, v in enumerate([recall * 100]):
        plt.text(i, v + 0.5, f'{v:.2f}%')

    plt.ylim(0, 105)
    plt.grid(True)
    plt.show()

    # F1 SCORE GRAPH
    plt.figure(figsize=(6,4))
    plt.bar(['F1-Score'], [f1 * 100])
    plt.title('F1-Score (%)')
    plt.ylabel('Percentage (%)')

    for i, v in enumerate([f1 * 100]):
        plt.text(i, v + 0.5, f'{v:.2f}%')

    plt.ylim(0, 105)
    plt.grid(True)
    plt.show()

    # COMBINED GRAPH
    plt.figure(figsize=(8,5))

    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    values = [
        accuracy,
        precision * 100,
        recall * 100,
        f1 * 100
    ]

    bars = plt.bar(metrics, values)

    plt.title('FbRSAEF Performance Metrics')
    plt.ylabel('Percentage (%)')
    plt.ylim(0, 105)

    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width()/2,
            height + 0.5,
            f'{height:.2f}%',
            ha='center'
        )

    plt.grid(True)
    plt.show()
    # Privacy Leakage
    privacy_leakage = THRESHOLD/NUM_SHARES
    shout_print(f"PRIVACY LEAKAGE (THRESHOLD/TOTAL_SHARES): {privacy_leakage:.2f}")

    #Classification Report & Confusion Matrix
    # For demo, use a simple row-wise label if present, otherwise row_id
    if 'Survived' in df.columns:
        y_true = df['Survived']
        y_pred = pd.DataFrame(decrypted_rows)['Survived']
        print("\nCLASSIFICATION REPORT:")
        print(classification_report(y_true, y_pred))
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(6,5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title("Confusion Matrix")
        plt.ylabel("True Label")
        plt.xlabel("Predicted Label")
        plt.show()

    # Graphs for Encryption & Decryption Time
    plt.figure(figsize=(6,4))
    plt.bar(['Encryption','Decryption'], [encryption_time,decryption_time], color=['orange','green'])
    plt.title("Encryption & Decryption Time (seconds)")
    plt.ylabel("Time (s)")
    plt.show()

    # Latency per row graph
    plt.figure(figsize=(6,4))
    plt.bar(['Latency per Row'], [total_time/total_rows], color='purple')
    plt.title("Latency per Row (seconds)")
    plt.ylabel("Time (s)")
    plt.show()

# Run Analysis
if __name__=="__main__":
    performance_analysis()