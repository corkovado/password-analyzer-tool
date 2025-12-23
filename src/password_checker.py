"""
Модуль для проверки паролей на безопасность
"""

import hashlib
import re
import requests
import time
from typing import Dict, Optional


class PasswordAPIError(Exception):
    """Кастомное исключение для ошибок API"""
    pass


def check_password_complexity(password: str) -> Dict:
    """Проверка пароля на соответствие политикам сложности"""
    
    # Добавляем проверку на пустой пароль
    if not password:
        return {
            "strength": "Очень слабый",
            "score": 0,
            "details": {
                "length_ok": False,
                "has_upper": False,
                "has_lower": False,
                "has_digit": False,
                "has_special": False,
                "no_common_patterns": False
            }
        }
    
    results = {
        "length_ok": len(password) >= 8,
        "has_upper": bool(re.search(r'[A-ZА-Я]', password)),
        "has_lower": bool(re.search(r'[a-zа-я]', password)),
        "has_digit": bool(re.search(r'\d', password)),
        "has_special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        "no_common_patterns": not any([
            password.lower() in [
                "password", "123456", "qwerty", "admin", "welcome",
                "monkey", "letmein", "dragon", "baseball", "football",
                "master", "hello", "freedom", "whatever", "qazwsx",
                "password1", "superman", "1q2w3e4r", "1qaz2wsx"
            ],
            len(set(password)) < 4,  # Слишком мало уникальных символов
            re.search(r'(.)\1{3,}', password),  # 4+ одинаковых символов подряд
            re.search(r'(0123|1234|2345|3456|4567|5678|6789|7890)', password),
            re.search(r'(qwer|asdf|zxcv|йцук|фыва|ячсм)', password.lower()),
            password.isdigit() and len(password) < 12,  # Только цифры и короткий
        ])
    }
    
    score = sum(results.values())
    
    if score >= 6:
        strength = "Очень сильный"
    elif score >= 4:
        strength = "Средний"
    elif score >= 2:
        strength = "Слабый"
    else:
        strength = "Очень слабый"
    
    return {
        "strength": strength,
        "score": score,
        "details": results
    }


def get_common_passwords_list() -> set:
    """Возвращает список самых распространенных паролей"""
    # Топ-100 самых слабых паролей
    common_passwords = {
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777",
        "121212", "000000", "qazwsx", "123qwe", "killer",
        "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
        "hunter", "buster", "soccer", "harley", "batman",
        "andrew", "tigger", "sunshine", "iloveyou", "2000",
        "charlie", "robert", "thomas", "hockey", "ranger",
        "daniel", "starwars", "klaster", "112233", "george",
        "computer", "michelle", "jessica", "pepper", "1111",
        "zxcvbn", "555555", "11111111", "131313", "freedom",
        "777777", "pass", "maggie", "159753", "aaaaaa",
        "ginger", "princess", "joshua", "cheese", "amanda",
        "summer", "love", "ashley", "nicole", "chelsea",
        "biteme", "matthew", "access", "yankees", "987654321",
        "dallas", "austin", "thunder", "taylor", "matrix"
    }
    return common_passwords


def check_password_breach(password: str, use_api: bool = True, max_retries: int = 2) -> Dict:
    """
    Проверка пароля на наличие в утечках
    Возвращает словарь с результатами проверки
    """
    
    # Сначала проверяем локальную базу распространенных паролей
    common_passwords = get_common_passwords_list()
    if password in common_passwords or password.lower() in common_passwords:
        return {
            "breached": True,
            "count": 1000000,  # Условно большое число
            "message": "Пароль найден в списке самых распространенных паролей!",
            "source": "local_db"
        }
    
    if not use_api:
        return {
            "breached": False,
            "count": 0,
            "message": "Проверка через API отключена",
            "source": "disabled"
        }
    
    # Проверяем через API HaveIBeenPwned с повторными попытками
    for attempt in range(max_retries + 1):
        try:
            # Хешируем пароль в SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Настраиваем заголовки для запроса
            headers = {
                'User-Agent': 'Password-Analyzer-CLI/1.0',
                'Accept': 'application/json'
            }
            
            # Отправляем запрос к API с таймаутом
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            
            print(f"  Попытка подключения к API ({attempt + 1}/{max_retries + 1})...")
            
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10  # Увеличиваем таймаут
            )
            
            if response.status_code == 200:
                # Парсим ответ
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return {
                            "breached": True,
                            "count": int(count),
                            "message": f"Пароль найден в {count:,} утечках!".replace(",", " "),
                            "source": "haveibeenpwned"
                        }
                
                return {
                    "breached": False,
                    "count": 0,
                    "message": "Пароль не найден в известных утечках",
                    "source": "haveibeenpwned"
                }
            
            elif response.status_code == 429:
                # Слишком много запросов
                if attempt < max_retries:
                    wait_time = 2 ** attempt  # Экспоненциальная задержка
                    print(f"  Слишком много запросов. Ждем {wait_time} секунд...")
                    time.sleep(wait_time)
                    continue
                else:
                    return {
                        "breached": False,
                        "count": 0,
                        "message": "Превышен лимит запросов к API. Попробуйте позже.",
                        "source": "rate_limit"
                    }
            
            else:
                # Другие ошибки HTTP
                return {
                    "breached": False,
                    "count": 0,
                    "message": f"Ошибка API: {response.status_code}",
                    "source": "http_error"
                }
        
        except requests.exceptions.Timeout:
            if attempt < max_retries:
                print(f"  Таймаут. Повторная попытка через 2 секунды...")
                time.sleep(2)
                continue
            return {
                "breached": False,
                "count": 0,
                "message": "Таймаут при подключении к API",
                "source": "timeout"
            }
        
        except requests.exceptions.ConnectionError as e:
            if attempt < max_retries:
                print(f"  Ошибка подключения. Повтор через 3 секунды...")
                time.sleep(3)
                continue
            
            # Подробная диагностика ошибки подключения
            error_msg = "Не удалось подключиться к API"
            if "SSL" in str(e):
                error_msg += " (ошибка SSL сертификата)"
            elif "Proxy" in str(e):
                error_msg += " (проблема с прокси)"
            
            return {
                "breached": False,
                "count": 0,
                "message": error_msg,
                "source": "connection_error",
                "details": str(e)
            }
        
        except requests.exceptions.RequestException as e:
            return {
                "breached": False,
                "count": 0,
                "message": f"Ошибка при запросе к API: {str(e)[:50]}",
                "source": "request_error"
            }
    
    return {
        "breached": False,
        "count": 0,
        "message": "Не удалось выполнить проверку после нескольких попыток",
        "source": "max_retries_exceeded"
    }


def check_password_strength_score(password: str) -> int:
    """Расчет числовой оценки силы пароля (0-100)"""
    if not password:
        return 0
    
    score = 0
    
    # Длина пароля (максимум 30 баллов)
    length = len(password)
    if length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    
    # Разнообразие символов (максимум 40 баллов)
    char_types = 0
    if re.search(r'[a-z]', password):
        char_types += 1
    if re.search(r'[A-Z]', password):
        char_types += 1
    if re.search(r'\d', password):
        char_types += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        char_types += 1
    
    score += char_types * 10
    
    # Энтропия (максимум 30 баллов)
    unique_chars = len(set(password))
    entropy_score = min(unique_chars / length * 30, 30)
    score += entropy_score
    
    # Штрафы за слабые паттерны
    if re.search(r'(.)\1{2,}', password):  # 3+ одинаковых символа подряд
        score -= 20
    if password.isdigit() or password.isalpha():
        score -= 15
    if password.lower() in get_common_passwords_list():
        score = 0  # Если пароль в списке слабых - обнуляем оценку
    
    return max(0, min(100, int(score)))


def check_password(password: str, use_api: bool = True, verbose: bool = True) -> Dict:
    """Основная функция проверки пароля"""
    
    if verbose:
        print("\n" + "=" * 40)
        print("РЕЗУЛЬТАТЫ ПРОВЕРКИ")
        print("=" * 40)
    
    # Проверка сложности
    complexity = check_password_complexity(password)
    
    if verbose:
        print(f"\n1. Анализ сложности:")
        print(f"   • Уровень безопасности: {complexity['strength']} ({complexity['score']}/7)")
        print(f"   • Длина >= 8 символов: {'✓' if complexity['details']['length_ok'] else '✗'}")
        print(f"   • Содержит заглавные буквы: {'✓' if complexity['details']['has_upper'] else '✗'}")
        print(f"   • Содержит строчные буквы: {'✓' if complexity['details']['has_lower'] else '✗'}")
        print(f"   • Содержит цифры: {'✓' if complexity['details']['has_digit'] else '✗'}")
        print(f"   • Содержит спецсимволы: {'✓' if complexity['details']['has_special'] else '✗'}")
        print(f"   • Без очевидных паттернов: {'✓' if complexity['details']['no_common_patterns'] else '✗'}")
    
    # Проверка на утечки
    breach_check = check_password_breach(password, use_api)
    
    if verbose:
        print(f"\n2. Проверка в базах утечек:")
        print(f"   • Источник проверки: {breach_check.get('source', 'unknown')}")
        print(f"   • Результат: {breach_check['message']}")
        
        if breach_check['breached']:
            print(f"   ⚠️  ВНИМАНИЕ: Этот пароль скомпрометирован!")
            print(f"   ⚠️  Рекомендуется немедленно его заменить!")
    
    # Расчет общей оценки
    strength_score = check_password_strength_score(password)
    
    if verbose:
        print(f"\n3. Общая оценка безопасности:")
        print(f"   • Оценка (0-100): {strength_score}/100")
        
        # Визуализация оценки
        bars = "█" * (strength_score // 5) + "░" * (20 - (strength_score // 5))
        print(f"   • Шкала: [{bars}]")
        
        if strength_score >= 80:
            print("   • Вердикт: Отличный пароль!")
        elif strength_score >= 60:
            print("   • Вердикт: Хороший пароль")
        elif strength_score >= 40:
            print("   • Вердикт: Приемлемый пароль")
        elif strength_score >= 20:
            print("   • Вердикт: Слабый пароль")
        else:
            print("   • Вердикт: Очень слабый пароль")
    
    # Общие рекомендации
    if verbose:
        print(f"\n4. Рекомендации:")
        
        if complexity['score'] >= 6 and not breach_check['breached'] and strength_score >= 70:
            print("   ✓ Пароль надежный! Можете его использовать.")
        else:
            recommendations = []
            
            if not complexity['details']['length_ok']:
                recommendations.append("Увеличьте длину пароля до 12+ символов")
            if not complexity['details']['has_upper']:
                recommendations.append("Добавьте заглавные буквы")
            if not complexity['details']['has_lower']:
                recommendations.append("Добавьте строчные буквы")
            if not complexity['details']['has_digit']:
                recommendations.append("Добавьте цифры")
            if not complexity['details']['has_special']:
                recommendations.append("Добавьте специальные символы")
            if not complexity['details']['no_common_patterns']:
                recommendations.append("Избегайте очевидных паттернов")
            if breach_check['breached']:
                recommendations.append("Немедленно замените пароль")
            
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
            
            print(f"\n   💡 Советы:")
            print("   • Используйте генератор паролей: python src/main.py -g -l 16")
            print("   • Используйте менеджер паролей (Bitwarden, KeePass)")
            print("   • Включайте двухфакторную аутентификацию где возможно")
            print("   • Регулярно меняйте важные пароли")
    
    return {
        "complexity": complexity,
        "breach_check": breach_check,
        "strength_score": strength_score,
        "is_secure": complexity['score'] >= 6 and not breach_check['breached'] and strength_score >= 70
    }


def check_passwords_from_file(filepath: str, use_api: bool = True) -> None:
    """Проверка нескольких паролей из файла"""
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        print(f"\nНайдено паролей для проверки: {len(passwords)}")
        
        results = []
        for i, password in enumerate(passwords, 1):
            print(f"\n[{i}/{len(passwords)}] Проверка пароля...")
            result = check_password(password, use_api, verbose=False)
            results.append(result)
            
            # Краткий вывод для каждого пароля
            stars = "*" * min(len(password), 10) + ("*" if len(password) > 10 else "")
            print(f"   Пароль: {stars}")
            print(f"   Оценка: {result['strength_score']}/100 - {result['complexity']['strength']}")
            if result['breach_check']['breached']:
                print(f"   ⚠️  Скомпрометирован!")
        
        # Сводная статистика
        strong_count = sum(1 for r in results if r['strength_score'] >= 70)
        breached_count = sum(1 for r in results if r['breach_check']['breached'])
        avg_score = sum(r['strength_score'] for r in results) / len(results) if results else 0
        
        print("\n" + "=" * 50)
        print("СВОДНАЯ СТАТИСТИКА")
        print("=" * 50)
        print(f"• Всего проверено паролей: {len(passwords)}")
        print(f"• Средняя оценка безопасности: {avg_score:.1f}/100")
        print(f"• Надежных паролей (≥70): {strong_count}")
        print(f"• Скомпрометированных паролей: {breached_count}")
        print(f"• Слабых паролей (<40): {sum(1 for r in results if r['strength_score'] < 40)}")
        
        if breached_count > 0:
            print(f"\n⚠️  ВНИМАНИЕ: {breached_count} паролей необходимо заменить!")
            print("   Эти пароли были скомпрометированы в утечках данных.")
        
        if strong_count == len(passwords):
            print(f"\n🎉 Отлично! Все пароли надежны!")
        elif strong_count / len(passwords) >= 0.7:
            print(f"\n👍 Хорошо! Большинство паролов надежны.")
        else:
            print(f"\n🔴 Требуется улучшение! Много слабых паролей.")
        
        # Рекомендации по улучшению
        print(f"\n📋 Рекомендации по улучшению безопасности:")
        if breached_count > 0:
            print(f"   1. Замените {breached_count} скомпрометированных паролей")
        if strong_count < len(passwords):
            print(f"   2. Улучшите {len(passwords) - strong_count} слабых паролей")
        print(f"   3. Используйте команду для генерации: python src/main.py -g -l 16")
        
    except FileNotFoundError:
        print(f"❌ Ошибка: Файл '{filepath}' не найден!")
        print(f"   Убедитесь, что файл существует по указанному пути.")
    except PermissionError:
        print(f"❌ Ошибка: Нет прав для чтения файла '{filepath}'")
    except UnicodeDecodeError:
        print(f"❌ Ошибка: Невозможно прочитать файл '{filepath}' как текст в кодировке UTF-8")
    except Exception as e:
        print(f"❌ Неожиданная ошибка при чтении файла: {e}")