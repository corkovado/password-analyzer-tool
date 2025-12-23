#!/usr/bin/env python3
"""
Скрипт для тестирования подключения к API
"""

import requests
import socket
import ssl
import sys


def check_internet_connection():
    """Проверяет наличие интернет-соединения"""
    print("🔍 Проверка интернет-соединения...")
    
    try:
        # Пробуем подключиться к DNS серверу Google
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("✅ Интернет-соединение: OK")
        return True
    except OSError:
        print("❌ Нет интернет-соединения")
        return False


def check_api_availability():
    """Проверяет доступность API HaveIBeenPwned"""
    print("\n🔍 Проверка доступности API HaveIBeenPwned...")
    
    try:
        # Пробуем простой запрос
        response = requests.get(
            "https://api.pwnedpasswords.com/range/5BAA6",
            headers={'User-Agent': 'Connection-Test'},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ API HaveIBeenPwned: Доступно")
            return True
        else:
            print(f"❌ API HaveIBeenPwned: Ошибка {response.status_code}")
            return False
    
    except requests.exceptions.Timeout:
        print("❌ API HaveIBeenPwned: Таймаут (слишком долгий ответ)")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ API HaveIBeenPwned: Ошибка подключения")
        print(f"   Детали: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ API HaveIBeenPwned: Ошибка запроса")
        print(f"   Детали: {e}")
        return False


def check_proxy_settings():
    """Проверяет настройки прокси"""
    print("\n🔍 Проверка настроек прокси...")
    
    proxies = requests.utils.get_environ_proxies('https://api.pwnedpasswords.com')
    
    if proxies:
        print(f"⚠️  Обнаружены настройки прокси:")
        for key, value in proxies.items():
            print(f"   {key}: {value}")
        print("\n💡 Совет: Если у вас проблемы с подключением,")
        print("   попробуйте отключить прокси или использовать VPN")
        return True
    else:
        print("✅ Прокси: Не настроены")
        return False


def check_ssl_certificates():
    """Проверяет SSL сертификаты"""
    print("\n🔍 Проверка SSL сертификатов...")
    
    try:
        # Пробуем получить SSL сертификат
        hostname = 'api.pwnedpasswords.com'
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("✅ SSL сертификаты: В порядке")
                return True
    except ssl.SSLCertVerificationError as e:
        print(f"❌ Ошибка верификации SSL сертификата: {e}")
        print("💡 Совет: Проверьте дату и время на компьютере")
        return False
    except Exception as e:
        print(f"❌ Ошибка SSL: {e}")
        return False


def main():
    print("=" * 60)
    print("🛠️  ДИАГНОСТИКА ПОДКЛЮЧЕНИЯ К API")
    print("=" * 60)
    
    tests_passed = 0
    total_tests = 4
    
    # Запускаем все проверки
    if check_internet_connection():
        tests_passed += 1
    
    if check_ssl_certificates():
        tests_passed += 1
    
    check_proxy_settings()  # Информационная проверка
    
    if check_api_availability():
        tests_passed += 1
    
    print("\n" + "=" * 60)
    print("📊 РЕЗУЛЬТАТЫ ДИАГНОСТИКИ")
    print("=" * 60)
    print(f"Пройдено тестов: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("🎉 Все тесты пройдены! API должно работать корректно.")
    elif tests_passed >= 2:
        print("⚠️  Есть некоторые проблемы, но базовые функции будут работать.")
        print("   Вы можете использовать флаг --no-api для локальной проверки.")
    else:
        print("❌ Критические проблемы с подключением.")
        print("\n💡 РЕКОМЕНДАЦИИ:")
        print("1. Проверьте интернет-подключение")
        print("2. Попробуйте отключить брандмауэр/антивирус")
        print("3. Проверьте настройки прокси/VPN")
        print("4. Используйте флаг --no-api: python src/main.py -c 'пароль' --no-api")
    
    print("\nДля проверки пароля без API используйте:")
    print('  python src/main.py -c "ваш_пароль" --no-api')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nДиагностика прервана пользователем")
        sys.exit(0)