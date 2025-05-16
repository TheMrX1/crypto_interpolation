import secrets
import hashlib

class PIE:
    def __init__(self, p, k):
        self.p = p
        self.k = k

    def _is_prime(self, n):
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True

    def _modular_inverse(self, n, modulus):
        return pow(n, -1, modulus)

    def generate_key(self):
        K_X = []
        num_points = self.k + 1
        while len(K_X) < num_points:
            point = secrets.randbelow(self.p - 1) + 1
            if point not in K_X:
                K_X.append(point)

        K_S = secrets.token_bytes(32)
        return K_X, K_S

    def _generate_random_coeffs(self, K_S, nonce):
        coeffs = []
        nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big') if isinstance(nonce, int) else nonce

        for i in range(self.k):
            hasher_input = K_S + nonce_bytes + i.to_bytes(2, 'big')
            h = hashlib.sha256(hasher_input).digest()
            num_bytes_for_p = (self.p.bit_length() + 7) // 8
            val_from_hash = int.from_bytes(h[:num_bytes_for_p], 'big')
            coeffs.append(val_from_hash % self.p)
        return coeffs

    def encrypt(self, message, K_X, K_S, nonce):
        random_coeffs = self._generate_random_coeffs(K_S, nonce)
        y_values = []
        for x_j in K_X:
            val = message % self.p
            current_x_j_power = 1
            for coeff_ai in random_coeffs:
                current_x_j_power = (current_x_j_power * x_j) % self.p
                term = (coeff_ai * current_x_j_power) % self.p
                val = (val + term) % self.p
            y_values.append(val)

        return y_values, random_coeffs

    def _lagrange_interpolate_at_zero(self, points_x, points_y):
        P_at_zero = 0
        num_of_points = len(points_x)

        for j in range(num_of_points):
            y_j = points_y[j]
            x_j = points_x[j]
            L_j_numerator = 1
            L_j_denominator = 1
            for i in range(num_of_points):
                if i == j:
                    continue
                x_i = points_x[i]
                L_j_numerator = (L_j_numerator * (-x_i + self.p)) % self.p
                L_j_denominator = (L_j_denominator * (x_j - x_i + self.p)) % self.p

            L_j_at_zero = (L_j_numerator * self._modular_inverse(L_j_denominator, self.p)) % self.p
            term = (y_j * L_j_at_zero) % self.p
            P_at_zero = (P_at_zero + term) % self.p

        return P_at_zero

    def decrypt(self, ciphertext_y_values, K_X):
        decrypted_message = self._lagrange_interpolate_at_zero(K_X, ciphertext_y_values)
        return decrypted_message

# --- Пример k=3 ---
if __name__ == "__main__":
    p_val = 101
    k_val = 3

    print(f"--- Просто демонстрация для k={k_val}, p={p_val} ---")
    # P.s. Если кто-то это читает (конечно же нет)... Демка тут потому, что я не придумал, как интерактив реализовать...

    pie_cipher = PIE(p=p_val, k=k_val)
    K_X_secret = [5, 12, 23, 30]
    K_S_secret = b'fixed_seed_for_k3_example_0123'

    print(f"Используемые секретные точки K_X: {K_X_secret}")
    print(f"Используемый секретный сид K_S: {K_S_secret.hex()}")

    message_to_encrypt = 57
    nonce_val = 12345
    # эта штука не важна для логики, просто она используется для предотвращения Replay Attacks

    print(f"\nШифруем сообщение: {message_to_encrypt}")
    try:
        ciphertext, generated_coeffs = pie_cipher.encrypt(message_to_encrypt, K_X_secret, K_S_secret, nonce_val)
        print(f"Сгенерированные случайные коэффициенты [a_1, a_2, a_3]: {generated_coeffs}")
        print(f"Полином P(x) = {message_to_encrypt} + {generated_coeffs[0]}*x + {generated_coeffs[1]}*x^2 + {generated_coeffs[2]}*x^3 (mod {p_val})")
        print(f"Шифртекст (значения P(x_j)): {ciphertext}")

        M_val = message_to_encrypt
        a1, a2, a3 = generated_coeffs[0], generated_coeffs[1], generated_coeffs[2]
        x0 = K_X_secret[0] # 5

        P_at_x0_manual = (M_val + \
                         (a1 * x0) % p_val + \
                         (a2 * pow(x0, 2, p_val)) % p_val + \
                         (a3 * pow(x0, 3, p_val)) % p_val \
                        ) % p_val
        print(f"Ручная проверка P({x0}): {P_at_x0_manual} (p.s. оно должно совпасть с C[0]={ciphertext[0]})")
        assert P_at_x0_manual == ciphertext[0]

        decrypted_msg = pie_cipher.decrypt(ciphertext, K_X_secret)
        print(f"\nДешифрованное сообщение: {decrypted_msg}")

    except ValueError as e:
        print(f"Произошла ошибка: {e}")
