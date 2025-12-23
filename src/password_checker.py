import hashlib
import requests
import re
from typing import Dict, List, Tuple
import json
import os


class PasswordChecker:
    def __init__(self):
        self.leaked_passwords_cache = set()
        self.load_cache()
    
    def load_cache(self) -> None:
        """Загружаем кэш скомпрометированных паролей из файла"""
        cache_file = "leaked_passwords.txt"
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    self.leaked_passwords_cache = set(line.strip() for line in f)
                print(f"Загружено {len(self.leaked_passwords_cache)} паролей из кэша")
            except Exception as e:
                print(f"Ошибка загрузки кэша: {e}")
    
    def save_to_cache(self, password: str) -> None:
        """Сохраняем пароль в кэш"""
        cache_file = "leaked_passwords.txt"
        try:
            with open(cache_file, 'a', encoding='utf-8') as f:
                f.write(f"{password}\n")
            self.leaked_passwords_cache.add(password)
        except Exception as e:
            print(f"Ошибка сохранения в кэш: {e}")
    
    def check_complexity(self, password: str) -> Dict[str, bool]:
        """Проверка сложности пароля"""
        checks = {
            'length': len(password) >= 8,
            'uppercase': bool(re.search(r'[A-ZА-Я]', password)),
            'lowercase': bool(re.search(r'[a-zа-я]', password)),
            'digits': bool(re.search(r'\d', password)),
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'no_spaces': ' ' not in password,
            'no_common_patterns': not bool(
                re.search(r'^(123456|password|qwerty|admin|111111)', password.lower())
            )
        }
        return checks
    
    def calculate_strength_score(self, password: str) -> Tuple[int, str]:
        """Расчет балла сложности пароля"""
        score = 0
        checks = self.check_complexity(password)
        
        # Баллы за каждый критерий
        score += 10 if checks['length'] else 0
        score += 5 if checks['uppercase'] else 0
        score += 5 if checks['lowercase'] else 0
        score += 5 if checks['digits'] else 0
        score += 10 if checks['special'] else 0
        score += 5 if checks['no_common_patterns'] else 0
        
        # Бонусы за длину
        if len(password) >= 12:
            score += 10
        elif len(password) >= 16:
            score += 20
        
        # Оценка сложности
        if score >= 40:
            strength = "Очень сильный"
        elif score >= 30:
            strength = "Сильный"
        elif score >= 20:
            strength = "Средний"
        elif score >= 10:
            strength = "Слабый"
        else:
            strength = "Очень слабый"
        
        return score, strength
    
    def check_haveibeenpwned(self, password: str) -> Tuple[bool, int]:
        """
        Проверка пароля через HaveIBeenPwned API
        Использует k-анонимность: отправляем только первые 5 символов хеша
        """
        # Кодируем пароль в SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            # Отправляем запрос к API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                # Ищем наш хеш в ответе
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return True, int(count)
                return False, 0
            else:
                print(f"Ошибка API: {response.status_code}")
                return False, 0
                
        except requests.exceptions.RequestException as e:
            print(f"Ошибка подключения к API: {e}")
            # Проверяем локальный кэш
            if password in self.leaked_passwords_cache:
                return True, 1
            return False, 0
    
    def analyze_password(self, password: str) -> Dict:
        """Полный анализ пароля"""
        print(f"\n🔍 Анализ пароля: {'*' * len(password)}")
        
        # Проверка сложности
        checks = self.check_complexity(password)
        score, strength = self.calculate_strength_score(password)
        
        # Проверка в базах утечек
        is_leaked, leak_count = self.check_haveibeenpwned(password)
        
        if is_leaked:
            print(f"⚠️  ВНИМАНИЕ: Пароль найден в {leak_count} утечках!")
            self.save_to_cache(password)
        
        # Собираем результаты
        result = {
            'password': '*' * len(password),
            'length': len(password),
            'score': score,
            'strength': strength,
            'is_leaked': is_leaked,
            'leak_count': leak_count,
            'checks': checks,
            'recommendations': []
        }
        
        # Формируем рекомендации
        if not checks['length']:
            result['recommendations'].append("Увеличьте длину пароля до минимум 8 символов")
        if not checks['uppercase']:
            result['recommendations'].append("Добавьте заглавные буквы")
        if not checks['lowercase']:
            result['recommendations'].append("Добавьте строчные буквы")
        if not checks['digits']:
            result['recommendations'].append("Добавьте цифры")
        if not checks['special']:
            result['recommendations'].append("Добавьте специальные символы (!@#$% и т.д.)")
        if not checks['no_common_patterns']:
            result['recommendations'].append("Избегайте распространенных паттернов")
        if is_leaked:
            result['recommendations'].append("НЕМЕДЛЕННО смените этот пароль!")
        
        return result
    
    def check_multiple_passwords(self, passwords: List[str]) -> List[Dict]:
        """Анализ нескольких паролей"""
        results = []
        for password in passwords:
            results.append(self.analyze_password(password))
        return results