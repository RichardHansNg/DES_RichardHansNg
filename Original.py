from typing import List, Tuple

# ---------------- Conversion Utilities ---------------- #

def hex2bin(s: str) -> str:
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
          '4': "0100", '5': "0101", '6': "0110", '7': "0111",
          '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
          'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    s = s.upper()
    return ''.join(mp[ch] for ch in s)

def bin2hex(s: str) -> str:
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
          "0100": '4', "0101": '5', "0110": '6', "0111": '7',
          "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
          "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    return ''.join(mp[s[i:i+4]] for i in range(0, len(s), 4))

def bin2dec(binary: int) -> int:
    decimal, i = 0, 0
    while binary != 0:
        dec = binary % 10
        decimal += dec * (2 ** i)
        binary //= 10
        i += 1
    return decimal

def dec2bin(num: int) -> str:
    res = bin(num).replace("0b", "")
    while len(res) % 4 != 0:
        res = '0' + res
    return res

def permute(k: str, arr: List[int], n: int) -> str:
    return ''.join(k[arr[i]-1] for i in range(n))

def shift_left(k: str, nth_shifts: int) -> str:
    return k[nth_shifts:] + k[:nth_shifts]

def xor(a: str, b: str) -> str:
    return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))

# ---------------- DES Tables ---------------- #

initial_perm = [58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7]

exp_d = [32,1,2,3,4,5,4,5,
         6,7,8,9,8,9,10,11,
         12,13,12,13,14,15,16,17,
         16,17,18,19,20,21,20,21,
         22,23,24,25,24,25,26,27,
         28,29,28,29,30,31,32,1]

per = [16,7,20,21,29,12,28,17,
       1,15,23,26,5,18,31,10,
       2,8,24,14,32,27,3,9,
       19,13,30,6,22,11,4,25]

final_perm = [40,8,48,16,56,24,64,32,
              39,7,47,15,55,23,63,31,
              38,6,46,14,54,22,62,30,
              37,5,45,13,53,21,61,29,
              36,4,44,12,52,20,60,28,
              35,3,43,11,51,19,59,27,
              34,2,42,10,50,18,58,26,
              33,1,41,9,49,17,57,25]

sbox = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
     [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
     [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
     [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],

    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
     [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
     [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
     [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],

    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
     [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
     [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
     [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],

    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
     [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
     [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
     [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],

    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
     [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
     [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
     [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],

    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
     [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
     [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
     [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],

    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
     [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
     [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
     [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],

    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
     [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
     [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
     [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

# ---------------- Key Generation ---------------- #

def generate_round_keys(key_hex: str) -> Tuple[List[str], List[str]]:
    key = hex2bin(key_hex)
    keyp = [57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4]
    key = permute(key, keyp, 56)
    shift_table = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    key_comp = [14,17,11,24,1,5,3,28,15,6,21,10,
                23,19,12,4,26,8,16,7,27,20,13,2,
                41,52,31,37,47,55,30,40,51,45,33,48,
                44,49,39,56,34,53,46,42,50,36,29,32]
    left, right = key[0:28], key[28:56]
    rkb, rk = [], []
    for i in range(16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        combine = left + right
        round_key = permute(combine, key_comp, 48)
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    return rkb, rk

# ---------------- Encryption Core ---------------- #

def des_rounds(pt_hex: str, rkb: List[str], rk: List[str]) -> str:
    pt = hex2bin(pt_hex)
    pt = permute(pt, initial_perm, 64)
    print("Initial Permutation:", bin2hex(pt))
    left, right = pt[0:32], pt[32:64]

    for i in range(16):
        right_expanded = permute(right, exp_d, 48)
        xor_x = xor(right_expanded, rkb[i])
        sbox_str = ""
        for j in range(8):
            row = bin2dec(int(xor_x[j*6] + xor_x[j*6 + 5]))
            col = bin2dec(int(xor_x[j*6 + 1] + xor_x[j*6 + 2] + xor_x[j*6 + 3] + xor_x[j*6 + 4]))
            val = sbox[j][row][col]
            sbox_str += dec2bin(val)
        sbox_str = permute(sbox_str, per, 32)
        result = xor(left, sbox_str)
        left = result
        if i != 15:
            left, right = right, left
        print(f"Round {i+1:2d} -> L: {bin2hex(left)} | R: {bin2hex(right)} | K: {rk[i]}")

    combine = left + right
    cipher_bin = permute(combine, final_perm, 64)
    cipher_hex = bin2hex(cipher_bin)
    print("Final Permutation:", cipher_hex)
    return cipher_hex

# ---------------- Padding Helpers ---------------- #

def pkcs7_pad(data: bytes, block_size=8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == block_size:
        return data
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size=8) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        return data
    if data[-pad_len:] == bytes([pad_len])*pad_len:
        return data[:-pad_len]
    return data

# ---------------- High-level Functions ---------------- #

def encrypt_message(pt: bytes, key_hex: str) -> str:
    rkb, rk = generate_round_keys(key_hex)
    pt = pkcs7_pad(pt, 8)
    cipher = ""
    for i in range(0, len(pt), 8):
        block_hex = pt[i:i+8].hex().upper()
        print(f"\nEncrypting block {i//8 + 1}: {block_hex}")
        cipher += des_rounds(block_hex, rkb, rk)
    return cipher

def decrypt_message(ct_hex: str, key_hex: str) -> bytes:
    rkb, rk = generate_round_keys(key_hex)
    rkb.reverse(); rk.reverse()
    pt_bytes = b""
    for i in range(0, len(ct_hex), 16):
        block_hex = ct_hex[i:i+16]
        print(f"\nDecrypting block {i//16 + 1}: {block_hex}")
        plain_hex = des_rounds(block_hex, rkb, rk)
        pt_bytes += bytes.fromhex(plain_hex)
    return pkcs7_unpad(pt_bytes, 8)

# ---------------- Interactive CLI ---------------- #

def main():
    print("=== DES (Step-by-Step Transformation) ===")
    mode = input("Mode (e)ncrypt/(d)ecrypt: ").strip().lower()
    key_hex = input("Enter 16-hex key (e.g. AABB09182736CCDD): ").strip().upper()

    if mode == 'e':
        pt_input = input("Enter plaintext (hex or ASCII): ").strip()
        if all(c in "0123456789ABCDEFabcdef" for c in pt_input) and len(pt_input) % 16 == 0:
            pt_bytes = bytes.fromhex(pt_input)
        else:
            pt_bytes = pt_input.encode()
        cipher = encrypt_message(pt_bytes, key_hex)
        print("\nCiphertext:", cipher)
    elif mode == 'd':
        ct_hex = input("Enter ciphertext hex: ").strip().upper()
        plain_bytes = decrypt_message(ct_hex, key_hex)
        try:
            print("\nPlaintext:", plain_bytes.decode())
        except:
            print("\nPlaintext (raw bytes):", plain_bytes)
    else:
        print("Invalid mode.")

if __name__ == "__main__":
    main()