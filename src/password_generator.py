"""
Модуль для генерации безопасных паролей
"""

import random
import string


def generate_password(length=12):
    """Генерация безопасного пароля заданной длины"""
    
    if length < 8:
        print("Предупреждение: пароли короче 8 символов ненадежны!")
    
    # Определяем наборы символов
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Гарантируем наличие хотя бы одного символа из каждой категории
    password_chars = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    # Заполняем остаток длины случайными символами из всех категорий
    all_chars = lowercase + uppercase + digits + special
    password_chars += random.choices(all_chars, k=length - 4)
    
    # Перемешиваем символы
    random.shuffle(password_chars)
    
    return ''.join(password_chars)


def generate_passwords(count=5, length=12):
    """Генерация нескольких паролей"""
    
    passwords = []
    for i in range(count):
        password = generate_password(length)
        passwords.append(password)
    
    return passwords


if __name__ == "__main__":
    # Пример использования
    print("Пример сгенерированных паролей:")
    for i, pwd in enumerate(generate_passwords(3, 16), 1):
        print(f"{i}. {pwd}")