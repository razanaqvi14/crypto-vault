import streamlit as st


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
def prepare_text(text, for_encryption=True):
    text = text.upper().replace("J", "I")
    cleaned = ""
    i = 0
    while i < len(text):
        char = text[i]
        if not char.isalpha():
            i += 1
            continue
        if i + 1 < len(text) and text[i] == text[i + 1]:
            cleaned += char + "X"
            i += 1
        elif i + 1 < len(text):
            cleaned += char + text[i + 1]
            i += 2
        else:
            cleaned += char + "X"
            i += 1
    return cleaned


def generate_matrix(key):
    key = key.upper().replace("J", "I")
    seen = set()
    matrix = []
    for char in key:
        if char.isalpha() and char not in seen:
            seen.add(char)
            matrix.append(char)
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    return [matrix[i : i + 5] for i in range(0, 25, 5)]


def find_position(matrix, char):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return -1, -1


def playfair_encrypt(text, key):
    matrix = generate_matrix(key)
    text = prepare_text(text)
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            result += matrix[row1][(col1 + 1) % 5]
            result += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            result += matrix[(row1 + 1) % 5][col1]
            result += matrix[(row2 + 1) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    return result


def playfair_decrypt(text, key):
    matrix = generate_matrix(key)
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:
            result += matrix[row1][(col1 - 1) % 5]
            result += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            result += matrix[(row1 - 1) % 5][col1]
            result += matrix[(row2 - 1) % 5][col2]
        else:
            result += matrix[row1][col2]
            result += matrix[row2][col1]
    return result


# ------------------- Hill Cipher ------------------- #
def mod_inverse(a, m):
    """Modular inverse using extended Euclidean algorithm."""
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def process_text(text):
    """Remove non-letters, replace J with I, and pad with X if needed."""
    cleaned = "".join(filter(str.isalpha, text.upper())).replace("J", "I")
    if len(cleaned) % 2 != 0:
        cleaned += "X"
    return cleaned


def chunk_text(text, size=2):
    return [text[i : i + size] for i in range(0, len(text), size)]


def text_to_numbers(text):
    return [ord(char) - ord("A") for char in text]


def numbers_to_text(numbers):
    return "".join([chr(num % 26 + ord("A")) for num in numbers])


def encrypt(plaintext, key_matrix):
    plaintext = process_text(plaintext)
    pairs = chunk_text(plaintext)

    result = []
    for pair in pairs:
        nums = text_to_numbers(pair)
        x = (key_matrix[0][0] * nums[0] + key_matrix[0][1] * nums[1]) % 26
        y = (key_matrix[1][0] * nums[0] + key_matrix[1][1] * nums[1]) % 26
        result.extend([x, y])

    return numbers_to_text(result)


def decrypt(ciphertext, key_matrix):
    ciphertext = process_text(ciphertext)
    pairs = chunk_text(ciphertext)

    a, b = key_matrix[0]
    c, d = key_matrix[1]
    det = (a * d - b * c) % 26
    det_inv = mod_inverse(det, 26)

    if det_inv is None:
        return "❌ Key matrix is not invertible modulo 26."

    inv_matrix = [
        [(d * det_inv) % 26, (-b * det_inv) % 26],
        [(-c * det_inv) % 26, (a * det_inv) % 26],
    ]

    result = []
    for pair in pairs:
        nums = text_to_numbers(pair)
        x = (inv_matrix[0][0] * nums[0] + inv_matrix[0][1] * nums[1]) % 26
        y = (inv_matrix[1][0] * nums[0] + inv_matrix[1][1] * nums[1]) % 26
        result.extend([x, y])

    return numbers_to_text(result)


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
    key = st.text_input(
        "Enter 4 integers for 2x2 key matrix (comma-separated)",
        value="3,3,2,5",
        key="hill_key",
    )


if st.button("Run"):
    if not text.strip():
        st.warning("Please enter some text.")

    elif cipher_type == "Caesar Cipher":
        if mode == "🔒 Encrypt":
            result = caesar_encrypt(text, shift)
            st.success("🔐 Encrypted Text:")
            st.code(result, language="")
        else:
            result = caesar_decrypt(text, shift)
            st.success("🔓 Decrypted Text:")
            st.code(result, language="")

    elif cipher_type == "Vigenère Cipher":
        if not key.isalpha():
            st.error("Key must contain only alphabetic characters.")
        else:
            if mode == "🔒 Encrypt":
                result = vigenere_encrypt(text, key)
                st.success("🔐 Encrypted Text:")
                st.code(result, language="")
            else:
                result = vigenere_decrypt(text, key)
                st.success("🔓 Decrypted Text:")
                st.code(result, language="")

    elif cipher_type == "Vernam (OTP) Cipher":
        if not key.isalpha() or len(key) != len(text):
            st.error("Key must be alphabetic and match the length of the text.")
        else:
            if mode == "🔒 Encrypt":
                result = vernam_encrypt(text, key)
                st.success("🔐 Encrypted Text:")
                st.code(result, language="")
            else:
                result = vernam_decrypt(text, key)
                st.success("🔓 Decrypted Text:")
                st.code(result, language="")

    elif cipher_type == "Rail Fence Cipher":
        if mode == "🔒 Encrypt":
            result = rail_fence_encrypt(text, rails)
            st.success("🔐 Encrypted Text:")
            st.code(result, language="")
        else:
            result = rail_fence_decrypt(text, rails)
            st.success("🔓 Decrypted Text:")
            st.code(result, language="")

    elif cipher_type == "Row Columnar Cipher":
        if not key.isalpha():
            st.error("Key must be alphabetic.")
        else:
            if mode == "🔒 Encrypt":
                result = row_columnar_encrypt(text.replace(" ", ""), key)
                st.success("🔐 Encrypted Text:")
                st.code(result, language="")
            else:
                result = row_columnar_decrypt(text.replace(" ", ""), key)
                st.success("🔓 Decrypted Text:")
                st.code(result, language="")

    elif cipher_type == "Playfair Cipher":
        if not key.strip() or not text.strip():
            st.error("Please enter both key and text.")
        elif not key.isalpha():
            st.error("Key should only contain alphabetic characters.")
        else:
            if mode == "🔒 Encrypt":
                result = playfair_encrypt(text, key)
                st.success("🔐 Encrypted Text:")
                st.code(result, language="")
            else:
                result = playfair_decrypt(text.upper().replace("J", "I"), key)
                st.success("🔓 Decrypted Text:")
                st.code(result, language="")

    elif cipher_type == "Hill Cipher":
        try:
            key_parts = list(map(int, key.strip().split(",")))
            if len(key_parts) != 4:
                st.error("Please enter exactly 4 integers.")
            else:
                key_matrix = [
                    [key_parts[0], key_parts[1]],
                    [key_parts[2], key_parts[3]],
                ]

                if mode == "🔒 Encrypt":
                    result = encrypt(text, key_matrix)
                    st.success("🔐 Encrypted Text:")
                    st.code(result, language="")
                else:
                    result = decrypt(text, key_matrix)
                    if result.startswith("❌"):
                        st.error(result)
                    else:
                        st.success("🔓 Decrypted Text:")
                        st.code(result, language="")

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
