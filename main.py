import secrets # Для криптографически стойких случайных чисел
import hashlib

class PIE:
    def __init__(self, p, k):
        """
        Инициализация параметров алгоритма PIE.
        :param p: Большое простое число (модуль поля GF(p)).
        :param k: Степень "случайной" части полинома.
                  Количество точек в K_X будет k+1.
                  Количество случайных коэффициентов a_i будет k.
        """
        if not self._is_prime(p): # Простая проверка на простоту для небольших p
            # Для больших p нужна более серьезная проверка, например, Миллера-Рабина
            print(f"Warning: p={p} might not be a strong prime. For demo purposes only.")
        if k < 0:
            raise ValueError("Степень k не может быть отрицательной.")

        self.p = p
        self.k = k

    def _is_prime(self, n):
        """Простая проверка на простоту (не для криптографических целей)."""
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True

    def _modular_inverse(self, n, modulus):
        """Вычисляет модульное обратное n^-1 mod modulus."""
        return pow(n, -1, modulus) # Используем встроенную функцию pow

    def generate_key(self):
        """
        Генерирует секретный ключ (K_X, K_S).
        K_X: список из k+1 различных случайных ненулевых точек x_i.
        K_S: секретный сид (байтовая строка).
        """
        K_X = []
        # Генерируем k+1 различных ненулевых точек x_i
        # Точки должны быть в диапазоне [1, p-1]
        num_points = self.k + 1
        if num_points >= self.p: # num_points не может быть больше p-1, т.к. точки из [1, p-1]
            raise ValueError(f"Невозможно сгенерировать {num_points} различных ненулевых точек в GF({self.p}) (доступно {self.p-1})")

        # Для детерминированных примеров можно закомментировать secrets и задать K_X вручную
        # K_X = [5, 12, 23, 30] # Если k=3 и p достаточно большое
        while len(K_X) < num_points:
            point = secrets.randbelow(self.p - 1) + 1 # [1, p-1]
            if point not in K_X:
                K_X.append(point)

        K_S = secrets.token_bytes(32) # 256-битный секретный сид
        # Для детерминированных примеров:
        # K_S = b'my_secret_seed_for_testing_1234'
        return K_X, K_S

    def _generate_random_coeffs(self, K_S, nonce):
        """
        Генерирует k случайных коэффициентов a_1, ..., a_k из K_S и nonce.
        :param K_S: Секретный сид (bytes).
        :param nonce: Одноразовое число (int или bytes).
        :return: Список из k коэффициентов [a_1, ..., a_k].
        """
        coeffs = []
        nonce_bytes = nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big') if isinstance(nonce, int) else nonce

        for i in range(self.k): # Нам нужно k коэффициентов a_1, ..., a_k
            hasher_input = K_S + nonce_bytes + i.to_bytes(2, 'big')
            h = hashlib.sha256(hasher_input).digest()
            num_bytes_for_p = (self.p.bit_length() + 7) // 8
            val_from_hash = int.from_bytes(h[:num_bytes_for_p], 'big')
            coeffs.append(val_from_hash % self.p)
        return coeffs

    def encrypt(self, message, K_X, K_S, nonce):
        """
        Шифрует сообщение M.
        P(x) = M + a_1*x + a_2*x^2 + ... + a_k*x^k
        :param message: Целое число < p.
        :param K_X: Список секретных точек [x_0, ..., x_k].
        :param K_S: Секретный сид.
        :param nonce: Одноразовое число.
        :return: Шифртекст (список значений [y_0, ..., y_k]).
        """
        if not (0 <= message < self.p):
            raise ValueError(f"Сообщение {message} должно быть в диапазоне [0, {self.p-1}]")
        if len(K_X) != self.k + 1:
            raise ValueError(f"Длина K_X ({len(K_X)}) должна быть k+1 ({self.k+1})")

        random_coeffs = self._generate_random_coeffs(K_S, nonce) # [a_1, ..., a_k]

        y_values = []
        for x_j in K_X:
            # P(x) = M + a_1*x + a_2*x^2 + ... + a_k*x^k
            val = message % self.p # Это M
            current_x_j_power = 1
            for coeff_ai in random_coeffs: # a_1, a_2, ..., a_k
                current_x_j_power = (current_x_j_power * x_j) % self.p # x_j, x_j^2, ..., x_j^k
                term = (coeff_ai * current_x_j_power) % self.p
                val = (val + term) % self.p
            y_values.append(val)

        return y_values, random_coeffs # Возвращаем random_coeffs для демонстрации

    def _lagrange_interpolate_at_zero(self, points_x, points_y):
        """
        Вычисляет значение интерполяционного многочлена P(0) по точкам (points_x, points_y).
        P(0) = sum_{j=0 to k} y_j * L_j(0)
        L_j(0) = product_{i=0 to k, i != j} (-x_i) / (x_j - x_i)
        """
        if len(points_x) != len(points_y):
            raise ValueError("Количество точек x и y должно совпадать.")
        if len(points_x) != self.k + 1:
            raise ValueError(f"Ожидалось {self.k+1} точек для интерполяции, получено {len(points_x)}")

        P_at_zero = 0
        num_of_points = len(points_x) # это k+1

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

            if L_j_denominator == 0:
                raise ValueError("Знаменатель в полиноме Лагранжа равен нулю. Точки x не уникальны?")

            L_j_at_zero = (L_j_numerator * self._modular_inverse(L_j_denominator, self.p)) % self.p
            term = (y_j * L_j_at_zero) % self.p
            P_at_zero = (P_at_zero + term) % self.p

        return P_at_zero

    def decrypt(self, ciphertext_y_values, K_X):
        """
        Дешифрует шифртекст.
        :param ciphertext_y_values: Список [y_0, ..., y_k].
        :param K_X: Список секретных точек [x_0, ..., x_k].
        :return: Исходное сообщение M.
        """
        if len(K_X) != self.k + 1:
            raise ValueError(f"Длина K_X ({len(K_X)}) должна быть k+1 ({self.k+1})")
        if len(ciphertext_y_values) != self.k + 1:
            raise ValueError(f"Длина шифртекста ({len(ciphertext_y_values)}) должна быть k+1 ({self.k+1})")

        decrypted_message = self._lagrange_interpolate_at_zero(K_X, ciphertext_y_values)
        return decrypted_message

# --- Пример использования для k=3 ---
if __name__ == "__main__":
    p_val = 101  # Простое число
    k_val = 3    # Степень "случайной" части полинома (будет 3+1=4 точки)

    print(f"--- Демонстрация для k={k_val}, p={p_val} ---")
    pie_cipher = PIE(p=p_val, k=k_val)

    # 1. Генерация ключа (используем фиксированные значения для воспроизводимости примера)
    # K_X_secret, K_S_secret = pie_cipher.generate_key() # Случайная генерация
    K_X_secret = [5, 12, 23, 30]  # k+1 = 4 точки
    K_S_secret = b'fixed_seed_for_k3_example_0123' # Фиксированный сид

    print(f"Используемые секретные точки K_X: {K_X_secret}")
    print(f"Используемый секретный сид K_S: {K_S_secret.hex()}")

    # 2. Сообщение и nonce
    message_to_encrypt = 42
    nonce_val = 12345

    # 3. Шифрование
    print(f"\nШифруем сообщение: {message_to_encrypt} с nonce: {nonce_val}")
    try:
        # Модифицируем encrypt, чтобы он возвращал и a_i для демонстрации
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
        print(f"Ручная проверка P({x0}): {P_at_x0_manual} (должно совпасть с ciphertext[0]={ciphertext[0]})")
        assert P_at_x0_manual == ciphertext[0]

        decrypted_msg = pie_cipher.decrypt(ciphertext, K_X_secret)
        print(f"\nДешифрованное сообщение: {decrypted_msg}")

        if decrypted_msg == message_to_encrypt:
            print("Успех! Сообщение дешифровано корректно.")
        else:
            print("Ошибка! Дешифрованное сообщение не совпадает с исходным.")
        assert decrypted_msg == message_to_encrypt

    except ValueError as e:
        print(f"Произошла ошибка: {e}")
