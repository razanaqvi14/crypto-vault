import streamlit as st
import string
import numpy as np


# ------------------- Caesar Cipher ------------------- #
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ------------------- Vigenère Cipher ------------------- #
def generate_key(text, key):
    key = key.upper()
    expanded_key = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            expanded_key += key[key_index % len(key)]
            key_index += 1
        else:
            expanded_key += char
    return expanded_key


def vigenere_encrypt(text, key):
    result = ""
    key = generate_key(text, key)
    for i in range(len(text)):
        if text[i].isalpha():
            base = ord("A") if text[i].isupper() else ord("a")
            shift = ord(key[i].upper()) - ord("A")
            result += chr((ord(text[i]) - base + shift) % 26 + base)
        else:
            result += text[i]
    return result


def vigenere_decrypt(text, key):
    result = ""
    key = generate_key(text, key)
    for i in range(len(text)):
        if text[i].isalpha():
            base = ord("A") if text[i].isupper() else ord("a")
            shift = ord(key[i].upper()) - ord("A")
            result += chr((ord(text[i]) - base - shift) % 26 + base)
        else:
            result += text[i]
    return result


# ------------------- Vernam Cipher (OTP) ------------------- #
def vernam_encrypt(text, key):
    result = ""
    for t_char, k_char in zip(text.upper(), key.upper()):
        if t_char.isalpha() and k_char.isalpha():
            encrypted = chr(((ord(t_char) - 65) ^ (ord(k_char) - 65)) + 65)
            result += encrypted
        else:
            result += t_char
    return result


def vernam_decrypt(cipher, key):
    return vernam_encrypt(cipher, key)


# ------------------- Rail Fence Cipher ------------------- #
def rail_fence_encrypt(text, rails):
    if rails <= 1:
        return text

    rail = ["" for _ in range(rails)]
    direction_down = False
    row = 0

    for char in text:
        rail[row] += char
        if row == 0 or row == rails - 1:
            direction_down = not direction_down
        row += 1 if direction_down else -1

    return "".join(rail)


def rail_fence_decrypt(cipher, rails):
    if rails <= 1:
        return cipher

    pattern = [["\n" for _ in range(len(cipher))] for _ in range(rails)]

    direction_down = None
    row, col = 0, 0

    for i in range(len(cipher)):
        if row == 0:
            direction_down = True
        elif row == rails - 1:
            direction_down = False
        pattern[row][col] = "*"
        col += 1
        row += 1 if direction_down else -1

    index = 0
    for i in range(rails):
        for j in range(len(cipher)):
            if pattern[i][j] == "*" and index < len(cipher):
                pattern[i][j] = cipher[index]
                index += 1

    result = ""
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            direction_down = True
        elif row == rails - 1:
            direction_down = False
        result += pattern[row][col]
        col += 1
        row += 1 if direction_down else -1

    return result


# ------------------- Row Columnar Cipher ------------------- #
def row_columnar_encrypt(plaintext, key):
    key = key.upper()
    col_count = len(key)
    row_count = -(-len(plaintext) // col_count)

    grid = [["" for _ in range(col_count)] for _ in range(row_count)]
    index = 0
    for r in range(row_count):
        for c in range(col_count):
            if index < len(plaintext):
                grid[r][c] = plaintext[index]
                index += 1
            else:
                grid[r][c] = "X"

    key_order = sorted([(char, i) for i, char in enumerate(key)])

    ciphertext = ""
    for char, idx in key_order:
        for r in range(row_count):
            ciphertext += grid[r][idx]

    return ciphertext


def row_columnar_decrypt(ciphertext, key):
    key = key.upper()
    col_count = len(key)
    row_count = -(-len(ciphertext) // col_count)

    key_order = sorted([(char, i) for i, char in enumerate(key)])

    grid = [["" for _ in range(col_count)] for _ in range(row_count)]

    index = 0
    for _, col_idx in key_order:
        for r in range(row_count):
            if index < len(ciphertext):
                grid[r][col_idx] = ciphertext[index]
                index += 1

    plaintext = ""
    for r in range(row_count):
        for c in range(col_count):
            plaintext += grid[r][c]

    return plaintext.rstrip("X")


# ------------------- Playfair Cipher ------------------- #
def generate_playfair_matrix(key):
    key = key.upper().replace("J", "I")
    seen = set()
    matrix = []

    for char in key + string.ascii_uppercase:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)
    return [matrix[i : i + 5] for i in range(0, 25, 5)]


def prepare_playfair_text(text):
    text = text.upper().replace("J", "I")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = ""
        if (i + 1) < len(text):
            b = text[i + 1]
        else:
            b = "X"
        if a == b:
            result += a + "X"
            i += 1
        else:
            result += a + b
            i += 2
    if len(result) % 2 != 0:
        result += "X"
    return result


def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None


def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    text = prepare_playfair_text(plaintext)
    ciphertext = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext


def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = ""

    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext


# ------------------- Hill Cipher ------------------- #
def text_to_numbers(text):
    return [ord(c.upper()) - ord("A") for c in text]


def numbers_to_text(numbers):
    return "".join([chr(n % 26 + ord("A")) for n in numbers])


def prepare_hill_text(text):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += "X"
    return text


def hill_encrypt(plaintext, key):
    plaintext = prepare_hill_text(plaintext)
    key = key.upper()

    if len(key) != 4 or not key.isalpha():
        return "Key must be 4 alphabetic characters."

    key_matrix = np.array(text_to_numbers(key)).reshape(2, 2)

    result = ""
    for i in range(0, len(plaintext), 2):
        block = np.array(text_to_numbers(plaintext[i : i + 2]))
        cipher_block = np.dot(key_matrix, block) % 26
        result += numbers_to_text(cipher_block)

    return result


def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix))) % modulus
    det_inv = mod_inverse(det, modulus)
    if det_inv is None:
        return None

    adj = (
        np.array([[matrix[1][1], -matrix[0][1]], [-matrix[1][0], matrix[0][0]]])
        % modulus
    )

    return (det_inv * adj) % modulus


def hill_decrypt(ciphertext, key):
    ciphertext = prepare_hill_text(ciphertext)
    key = key.upper()

    if len(key) != 4 or not key.isalpha():
        return "Key must be 4 alphabetic characters."

    key_matrix = np.array(text_to_numbers(key)).reshape(2, 2)
    inv_matrix = matrix_mod_inv(key_matrix, 26)

    if inv_matrix is None:
        return "Key matrix is not invertible modulo 26."

    result = ""
    for i in range(0, len(ciphertext), 2):
        block = np.array(text_to_numbers(ciphertext[i : i + 2]))
        plain_block = np.dot(inv_matrix, block) % 26
        result += numbers_to_text(plain_block)

    return result


# ------------------- Streamlit UI ------------------- #
st.set_page_config(page_title="CryptoVault", page_icon="🔒", layout="centered")

st.markdown(
    """
    <h1 style='text-align: center; color: #4B8BBE;'>🔐 CryptoVault</h1>
    <h4 style='text-align: center; color: gray;'>	A secure vault of classical ciphers</h4>
""",
    unsafe_allow_html=True,
)

st.markdown("---")

cipher_type = st.selectbox(
    "Select Cipher:",
    [
        "Caesar Cipher",
        "Vigenère Cipher",
        "Vernam (OTP) Cipher",
        "Rail Fence Cipher",
        "Row Columnar Cipher",
        "Playfair Cipher",
        "Hill Cipher",
    ],
)


mode = st.radio(
    "Choose Mode:", ["🔒 Encrypt", "🔓 Decrypt"], horizontal=True, key="mode_radio"
)

text = st.text_area("Enter your text here:", height=150, key="input_text_area")

if cipher_type == "Caesar Cipher":
    shift = st.slider("Select Caesar Shift (0-25):", min_value=0, max_value=25, value=3)
elif cipher_type == "Vigenère Cipher":
    key = st.text_input("Enter Vigenère Key (Alphabet only):", key="vig_key")
elif cipher_type == "Vernam (OTP) Cipher":
    key = st.text_input(
        "Enter Vernam (OTP) Key (Same length as text, A-Z only):", key="vernam_key"
    )
elif cipher_type == "Rail Fence Cipher":
    rails = st.slider("Select Number of Rails:", min_value=2, max_value=10, value=3)
elif cipher_type == "Row Columnar Cipher":
    key = st.text_input("Enter Columnar Key (Alphabet only):", key="row_col_key")
elif cipher_type == "Playfair Cipher":
    key = st.text_input("Enter Playfair Key (Alphabet only):", key="playfair_key")
elif cipher_type == "Hill Cipher":
    key = st.text_input("Enter Hill Cipher Key (4 letters only):", key="hill_key")


if st.button("Run"):
    if not text.strip():
        st.warning("Please enter some text.")
    elif cipher_type == "Caesar Cipher":
        if mode == "🔒 Encrypt":
            result = caesar_encrypt(text, shift)
        else:
            result = caesar_decrypt(text, shift)
        st.success(f"Result:\n\n{result}")
    elif cipher_type == "Vigenère Cipher":
        if not key.isalpha():
            st.error("Key must contain only alphabetic characters.")
        else:
            if mode == "🔒 Encrypt":
                result = vigenere_encrypt(text, key)
            else:
                result = vigenere_decrypt(text, key)
            st.success(f"Result:\n\n{result}")
    elif cipher_type == "Vernam (OTP) Cipher":
        if not key.isalpha() or len(key) != len(text):
            st.error("Key must be alphabetic and match the length of the text.")
        else:
            if mode == "🔒 Encrypt":
                result = vernam_encrypt(text, key)
            else:
                result = vernam_decrypt(text, key)
            st.success(f"Result:\n\n{result}")
    elif cipher_type == "Rail Fence Cipher":
        if mode == "🔒 Encrypt":
            result = rail_fence_encrypt(text, rails)
        else:
            result = rail_fence_decrypt(text, rails)
        st.success(f"Result:\n\n{result}")
    elif cipher_type == "Row Columnar Cipher":
        if not key.isalpha():
            st.error("Key must be alphabetic.")
        else:
            if mode == "🔒 Encrypt":
                result = row_columnar_encrypt(text.replace(" ", ""), key)
            else:
                result = row_columnar_decrypt(text.replace(" ", ""), key)
            st.success(f"Result:\n\n{result}")
    elif cipher_type == "Playfair Cipher":
        if not key.isalpha():
            st.error("Key must be alphabetic.")
        else:
            clean_text = text.replace(" ", "")
            if mode == "🔒 Encrypt":
                result = playfair_encrypt(clean_text, key)
            else:
                result = playfair_decrypt(clean_text, key)
            st.success(f"Result:\n\n{result}")
    elif cipher_type == "Hill Cipher":
        if len(key) != 4 or not key.isalpha():
            st.error("Key must be exactly 4 alphabetic letters (e.g., 'GYBN').")
        else:
            clean_text = text.replace(" ", "")
            if mode == "🔒 Encrypt":
                result = hill_encrypt(clean_text, key)
            else:
                result = hill_decrypt(clean_text, key)
            st.success(f"Result:\n\n{result}")
