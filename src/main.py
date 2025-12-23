def main():
    print("Мое приложение для анализа слабых паролей")
    
if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Анализатор слабых паролей - CLI утилита
"""

import argparse
import sys
from typing import List
from colorama import init, Fore, Style
from tabulate import tabulate

# Инициализация colorama для цветного вывода в Windows
init(autoreset=True)

# Импорт наших модулей
from password_checker import PasswordChecker
from password_generator import PasswordGenerator


def print_banner():
    """Вывод красивого баннера"""
    banner = f"""
{Fore.CYAN}{'='*60}
{Fore.YELLOW}  █████╗ ███╗   ██╗ █████╗ ██╗  ██╗ █████╗ ██████╗ 
{Fore.YELLOW} ██╔══██╗████╗  ██║██╔══██╗██║  ██║██╔══██╗██╔══██╗
{Fore.YELLOW} ███████║██╔██╗ ██║███████║███████║███████║██████╔╝
{Fore.YELLOW} ██╔══██║██║╚██╗██║██╔══██║██╔══██║██╔══██║██╔══██╗
{Fore.YELLOW} ██║  ██║██║ ╚████║██║  ██║██║  ██║██║  ██║██║  ██║
{Fore.YELLOW} ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{Fore.CYAN}{'='*60}
{Style.RESET_ALL}CLI утилита для анализа и генерации безопасных паролей
"""
    print(banner)


def print_result(result: dict):
    """Красивый вывод результатов анализа"""
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.YELLOW}📊 РЕЗУЛЬТАТЫ АНАЛИЗА:")
    print(f"{Fore.GREEN}{'='*60}")
    
    print(f"\n{Fore.CYAN}📈 Общая оценка:")
    print(f"  Длина: {Fore.WHITE}{result['length']} символов")
    print(f"  Балл сложности: {Fore.WHITE}{result['score']}/60")
    print(f"  Уровень защиты: {Fore.WHITE}{result['strength']}")
    
    if result['is_leaked']:
        print(f"  {Fore.RED}⚠️  Найден в утечках: {result['leak_count']} раз")
    
    print(f"\n{Fore.CYAN}✅ Проверки сложности:")
    checks = result['checks']
    check_icons = {
        True: f"{Fore.GREEN}✓",
        False: f"{Fore.RED}✗"
    }
    
    check_names = {
        'length': 'Длина ≥ 8 символов',
        'uppercase': 'Заглавные буквы',
        'lowercase': 'Строчные буквы',
        'digits': 'Цифры',
        'special': 'Специальные символы',
        'no_spaces': 'Без пробелов',
        'no_common_patterns': 'Нет простых паттернов'
    }
    
    for key, name in check_names.items():
        status = check_icons[checks[key]]
        print(f"  {status} {name}")
    
    if result['recommendations']:
        print(f"\n{Fore.YELLOW}💡 Рекомендации:")
        for rec in result['recommendations']:
            print(f"  • {rec}")
    
    print(f"\n{Fore.GREEN}{'='*60}")


def check_mode(args):
    """Режим проверки паролей"""
    checker = PasswordChecker()
    
    if args.password:
        # Проверка одного пароля
        result = checker.analyze_password(args.password)
        print_result(result)
        
    elif args.file:
        # Проверка паролей из файла
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                print(f"{Fore.RED}Файл пуст или не содержит паролей")
                return
            
            print(f"\n{Fore.CYAN}Проверяю {len(passwords)} паролей из файла...")
            results = checker.check_multiple_passwords(passwords)
            
            # Сводная таблица
            table_data = []
            for i, result in enumerate(results, 1):
                table_data.append([
                    i,
                    '*' * len(passwords[i-1]),
                    result['length'],
                    result['score'],
                    result['strength'],
                    f"{Fore.RED}ДА" if result['is_leaked'] else f"{Fore.GREEN}НЕТ",
                    result['leak_count'] if result['is_leaked'] else 0
                ])
            
            headers = ["№", "Пароль", "Длина", "Балл", "Уровень", "В утечках", "Кол-во утечек"]
            print(f"\n{Fore.YELLOW}📋 Сводная таблица:")
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
        except FileNotFoundError:
            print(f"{Fore.RED}Файл не найден: {args.file}")
    
    elif args.interactive:
        # Интерактивный режим
        print(f"\n{Fore.CYAN}🔐 Интерактивная проверка паролей")
        print(f"{Fore.YELLOW}(Введите 'exit' для выхода)")
        
        while True:
            try:
                password = input(f"\n{Fore.GREEN}Введите пароль для проверки: ")
                
                if password.lower() == 'exit':
                    break
                
                if password:
                    result = checker.analyze_password(password)
                    print_result(result)
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Выход из интерактивного режима")
                break


def generate_mode(args):
    """Режим генерации паролей"""
    generator = PasswordGenerator()
    
    if args.count > 1:
        print(f"\n{Fore.CYAN}Генерирую {args.count} паролей...\n")
    
    if args.type == 'memorable':
        # Запоминающиеся пароли
        for i in range(args.count):
            password = generator.generate_memorable_password(
                word_count=args.words,
                separator=args.separator,
                capitalize=not args.no_caps,
                add_number=not args.no_numbers
            )
            print(f"{Fore.GREEN}{i+1}. {password}")
    
    elif args.type == 'passphrase':
        # Пасфразы
        for i in range(args.count):
            password = generator.generate_passphrase(word_count=args.words)
            print(f"{Fore.GREEN}{i+1}. {password}")
    
    else:
        # Стандартные пароли
        for i in range(args.count):
            password = generator.generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_digits=not args.no_digits,
                use_special=not args.no_special
            )
            print(f"{Fore.GREEN}{i+1}. {password}")
    
    print(f"\n{Fore.YELLOW}💡 Совет: Сохраните пароли в надежном менеджере паролей!")


def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(
        description="Анализатор слабых паролей - проверка и генерация безопасных паролей",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s check -p "мойпароль123"      # Проверить один пароль
  %(prog)s check -i                     # Интерактивный режим
  %(prog)s check -f passwords.txt       # Проверить пароли из файла
  %(prog)s generate                     # Сгенерировать пароль
  %(prog)s generate -t memorable -c 5   # 5 запоминающихся паролей
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Доступные команды')
    
    # Парсер для команды check
    check_parser = subparsers.add_parser('check', help='Проверка паролей')
    check_group = check_parser.add_mutually_exclusive_group(required=True)
    check_group.add_argument('-p', '--password', help='Пароль для проверки')
    check_group.add_argument('-f', '--file', help='Файл с паролями для проверки')
    check_group.add_argument('-i', '--interactive', action='store_true', 
                           help='Интерактивный режим')
    
    # Парсер для команды generate
    gen_parser = subparsers.add_parser('generate', help='Генерация паролей')
    gen_parser.add_argument('-c', '--count', type=int, default=1,
                          help='Количество паролей (по умолчанию: 1)')
    gen_parser.add_argument('-l', '--length', type=int, default=12,
                          help='Длина пароля (по умолчанию: 12)')
    gen_parser.add_argument('-t', '--type', choices=['standard', 'memorable', 'passphrase'],
                          default='standard', help='Тип пароля (по умолчанию: standard)')
    gen_parser.add_argument('-w', '--words', type=int, default=4,
                          help='Количество слов для запоминающегося пароля')
    gen_parser.add_argument('-s', '--separator', default='-',
                          help='Разделитель слов (по умолчанию: -)')
    
    # Флаги для генерации
    gen_parser.add_argument('--no-upper', action='store_true',
                          help='Не использовать заглавные буквы')
    gen_parser.add_argument('--no-digits', action='store_true',
                          help='Не использовать цифры')
    gen_parser.add_argument('--no-special', action='store_true',
                          help='Не использовать специальные символы')
    gen_parser.add_argument('--no-caps', action='store_true',
                          help='Не использовать заглавные буквы в словах')
    gen_parser.add_argument('--no-numbers', action='store_true',
                          help='Не добавлять числа в запоминающиеся пароли')
    
    # Общие аргументы
    parser.add_argument('-v', '--version', action='version', 
                       version='Анализатор паролей v1.0.0')
    
    args = parser.parse_args()
    
    # Вывод баннера
    print_banner()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'check':
            check_mode(args)
        elif args.command == 'generate':
            generate_mode(args)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Произошла ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()