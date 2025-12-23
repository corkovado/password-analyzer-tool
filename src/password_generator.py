import random
import string
import secrets
from typing import List


class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.all_chars = self.lowercase + self.uppercase + self.digits + self.special
    
    def generate_password(self, length: int = 12, 
                         use_upper: bool = True,
                         use_digits: bool = True,
                         use_special: bool = True) -> str:
        """Генерация безопасного пароля с использованием secrets"""
        if length < 8:
            length = 8
        
        # Создаем пул символов
        chars = self.lowercase
        if use_upper:
            chars += self.uppercase
        if use_digits:
            chars += self.digits
        if use_special:
            chars += self.special
        
        # Гарантируем минимум по одному символу каждого типа
        password = []
        password.append(secrets.choice(self.lowercase))
        
        if use_upper:
            password.append(secrets.choice(self.uppercase))
        if use_digits:
            password.append(secrets.choice(self.digits))
        if use_special:
            password.append(secrets.choice(self.special))
        
        # Заполняем оставшуюся длину
        remaining_length = length - len(password)
        if remaining_length > 0:
            password.extend(secrets.choice(chars) for _ in range(remaining_length))
        
        # Перемешиваем
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_memorable_password(self, 
                                   word_count: int = 4,
                                   separator: str = '-',
                                   capitalize: bool = True,
                                   add_number: bool = True) -> str:
        """Генерация запоминающегося пароля из слов"""
        # Список простых слов (можно расширить)
        words = [
            'apple', 'banana', 'cherry', 'date', 'elderberry', 'fig', 'grape',
            'honeydew', 'kiwi', 'lemon', 'mango', 'nectarine', 'orange', 'papaya',
            'quince', 'raspberry', 'strawberry', 'tangerine', 'watermelon',
            'air', 'book', 'cat', 'dog', 'elephant', 'flower', 'garden', 'house',
            'ice', 'jungle', 'king', 'lion', 'mountain', 'night', 'ocean', 'planet',
            'queen', 'river', 'sun', 'tree', 'universe', 'valley', 'wind', 'xray', 'yoga', 'zebra'
        ]
        
        selected_words = secrets.SystemRandom().sample(words, word_count)
        
        # Модифицируем слова
        if capitalize:
            selected_words = [w.capitalize() for w in selected_words]
        
        password = separator.join(selected_words)
        
        if add_number:
            password += str(secrets.randbelow(100))
        
        return password
    
    def generate_passphrase(self, word_count: int = 6) -> str:
        """Генерация пасфразы (самый безопасный вариант)"""
        # Более обширный список слов
        wordlist = [
            'абрикос', 'банан', 'виноград', 'гранат', 'дыня', 'ежевика', 'женьшень',
            'зизифус', 'инжир', 'йогурт', 'карамбола', 'лимон', 'манго', 'нектарин',
            'орех', 'персик', 'рябина', 'слива', 'томат', 'урюк', 'фейхоа', 'хурма',
            'цитрон', 'черешня', 'шиповник', 'яблоко',
            'астрономия', 'биология', 'география', 'диаграмма', 'экология', 'физика',
            'гармония', 'информатика', 'йога', 'кибернетика', 'лингвистика', 'математика'
        ]
        
        return ' '.join(secrets.choice(wordlist) for _ in range(word_count))
    
    def generate_multiple(self, 
                         count: int = 5,
                         length: int = 12,
                         type: str = 'standard') -> List[str]:
        """Генерация нескольких паролей"""
        passwords = []
        for _ in range(count):
            if type == 'memorable':
                passwords.append(self.generate_memorable_password())
            elif type == 'passphrase':
                passwords.append(self.generate_passphrase())
            else:
                passwords.append(self.generate_password(length))
        return passwords