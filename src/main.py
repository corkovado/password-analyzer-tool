"""
Анализатор слабых паролей - CLI утилита
Проверяет пароли на безопасность и генерирует надежные пароли
"""

import argparse
import sys
from password_checker import check_password, check_passwords_from_file
from password_generator import generate_password, generate_passwords


def print_banner():
    """Печатает баннер приложения"""
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║          АНАЛИЗАТОР СЛАБЫХ ПАРОЛЕЙ               ║
    ║          🔐 Password Security Tool 🔐            ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Анализатор слабых паролей - проверка безопасности паролей",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s -c "MyP@ssw0rd123"     Проверить один пароль
  %(prog)s -g -l 16                Сгенерировать пароль из 16 символов
  %(prog)s -f passwords.txt        Проверить пароли из файла
  %(prog)s -c "test" --no-api      Проверить без подключения к интернету
  
Для подробной справки: %(prog)s --help
        """
    )
    
    # Создаем группу для взаимно исключающихся аргументов
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument(
        "-c", "--check",
        help="Проверить один пароль",
        metavar="PASSWORD"
    )
    
    group.add_argument(
        "-f", "--file",
        help="Проверить пароли из файла (каждый пароль на новой строке)",
        metavar="FILEPATH"
    )
    
    group.add_argument(
        "-g", "--generate",
        help="Сгенерировать безопасный пароль",
        action="store_true"
    )
    
    group.add_argument(
        "--generate-multiple",
        help="Сгенерировать несколько паролей",
        type=int,
        metavar="COUNT"
    )
    
    parser.add_argument(
        "-l", "--length",
        help="Длина генерируемого пароля (по умолчанию: 12)",
        type=int,
        default=12,
        choices=range(8, 65)  # От 8 до 64 символов
    )
    
    parser.add_argument(
        "--no-api",
        help="Не проверять через API (только локальная проверка)",
        action="store_true"
    )
    
    parser.add_argument(
        "--simple",
        help="Упрощенный вывод (только результат)",
        action="store_true"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        help="Подробный вывод (больше информации)",
        action="store_true"
    )
    
    parser.add_argument(
        "--version",
        help="Показать версию программы",
        action="version",
        version="Анализатор паролей v1.0.0"
    )
    
    args = parser.parse_args()
    
    if not args.simple:
        print_banner()
        print("=" * 60)
    
    try:
        if args.generate:
            password = generate_password(args.length)
            if args.simple:
                print(password)
            else:
                print(f"\n✨ Сгенерированный пароль: {password}")
                print("\n🔍 Проверяем его безопасность...")
                check_password(password, use_api=not args.no_api, verbose=not args.simple)
        
        elif args.generate_multiple:
            count = args.generate_multiple
            if count < 1 or count > 20:
                print("❌ Ошибка: количество должно быть от 1 до 20")
                sys.exit(1)
            
            passwords = generate_passwords(count, args.length)
            if args.simple:
                for pwd in passwords:
                    print(pwd)
            else:
                print(f"\n✨ Сгенерировано {count} паролей:")
                for i, pwd in enumerate(passwords, 1):
                    print(f"\n{i}. {pwd}")
                    check_password(pwd, use_api=not args.no_api, verbose=False)
                    print("-" * 40)
        
        elif args.check:
            if args.simple:
                result = check_password(args.check, use_api=not args.no_api, verbose=False)
                print(f"{result['strength_score']}")
            else:
                print(f"\n🔍 Проверка пароля...")
                check_password(args.check, use_api=not args.no_api, verbose=True)
        
        elif args.file:
            check_passwords_from_file(args.file, use_api=not args.no_api)
        
        if not args.simple:
            print("\n" + "=" * 60)
            print("✅ Проверка завершена!")
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Программа прервана пользователем")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()