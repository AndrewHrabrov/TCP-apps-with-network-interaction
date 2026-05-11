#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Клиент для обмена байтами с сервером.
Реализует требования ТЗ:
- подключение по TCP
- регистрация нового пользователя
- аутентификация, получение интервала от сервера
- отправка последовательностей байт с заданным интервалом
- обработка сетевых ошибок и автоматическое восстановление соединения
- закрытие соединения по протоколу (disconnect)
"""

import socket
import time
import random
import hashlib
import argparse
import sys
import threading
import re
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("client")


def hash_password(password: str) -> str:
    """SHA-256 хеш пароля (обрезанный до 32 символов)."""
    return hashlib.sha256(password.encode()).hexdigest()[:32]


def generate_client_id() -> str:
    """Генерация уникального идентификатора клиента (цифры 1-10 символов)."""
    return str(random.randint(1, 10**9 - 1))


def generate_message_id() -> int:
    """Генерация случайного messageID (1..32)."""
    return random.randint(1, 32)


def parse_response(line: str):
    """Разбор ответа сервера с поддержкой кавычек."""
    line = line.strip()
    if not line:
        return None, {}

    parts = []
    current = ""
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
            current += ch
        elif ch == ' ' and not in_quotes:
            if current:
                parts.append(current)
                current = ""
        else:
            current += ch
    if current:
        parts.append(current)

    if not parts:
        return None, {}

    command = parts[0]
    params = {}
    i = 1
    while i < len(parts):
        token = parts[i]
        if ':' in token and i + 1 < len(parts):
            key = token.rstrip(':')
            value = parts[i + 1]
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            params[key] = value
            i += 2
        else:
            i += 1
    return command, params


class Client:
    """Клиент для взаимодействия с сервером."""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.client_id = generate_client_id()
        self.authenticated = False
        self.username = None
        self.password_hash = None
        self.send_interval = 1000          # мс, будет заменён сервером
        self.running = False
        self.send_thread = None
        self.lock = threading.Lock()

    # ------------------- Вспомогательные методы -------------------
    def _close_socket(self):
        """Безопасное закрытие сокета."""
        with self.lock:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass
                self.sock = None

    def _send_raw_command(self, req: str, timeout: float = 2.0) -> str:
        """Отправить команду и получить ответ."""
        with self.lock:
            if not self.sock:
                raise ConnectionError("Нет соединения")
            self.sock.sendall((req + '\n').encode('utf-8'))
            self.sock.settimeout(timeout)
            resp = self.sock.recv(4096).decode('utf-8').strip()
            self.sock.settimeout(None)
            return resp

    def _handshake(self) -> bool:
        msg_id = generate_message_id()
        req = f"connection clientID: {self.client_id} messageID: {msg_id}"
        try:
            resp = self._send_raw_command(req)
            cmd, params = parse_response(resp)
            return cmd == "connection_success" and params.get("messageID") == str(msg_id)
        except Exception:
            return False

    def connect(self) -> bool:
        """Установить TCP-соединение и выполнить handshake."""
        try:
            self._close_socket()
            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new_sock.connect((self.host, self.port))
            with self.lock:
                self.sock = new_sock
            if self._handshake():
                logger.info("Подключение к серверу установлено.")
                return True
            else:
                self._close_socket()
                return False
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            return False

    def _reauth(self) -> bool:
        """Повторная аутентификация с сохранёнными данными."""
        if not self.username or not self.password_hash:
            return False
        msg_id = generate_message_id()
        req = f'auth messageID: {msg_id} username: "{self.username}" password_hash: "{self.password_hash}"'
        try:
            resp = self._send_raw_command(req)
            cmd, params = parse_response(resp)
            if cmd == "auth_success" and params.get("messageID") == str(msg_id):
                self.authenticated = True
                if "interval" in params:
                    try:
                        new_interval_sec = float(params["interval"])
                        self.send_interval = int(new_interval_sec * 1000)
                        print(f"Интервал отправки обновлён: {self.send_interval} мс")
                    except ValueError:
                        pass
                logger.info("Повторная аутентификация успешна.")
                return True
            else:
                return False
        except Exception:
            return False

    def ensure_connection_and_auth(self) -> bool:
        """Проверить соединение и аутентификацию, при необходимости восстановить."""
        if self.sock is None or not self.authenticated:
            if self.connect() and self._reauth():
                return True
            else:
                self.authenticated = False
                return False
        return True

    # ------------------- Основные команды -------------------
    def register(self, username, password) -> bool:
        """Регистрация нового пользователя."""
        if self.authenticated:
            print("Вы уже аутентифицированы.")
            return False
        if not self.sock and not self.connect():
            print("Не удалось подключиться к серверу.")
            return False
        msg_id = generate_message_id()
        pwd_hash = hash_password(password)
        req = f'register messageID: {msg_id} username: "{username}" password_hash: "{pwd_hash}"'
        try:
            resp = self._send_raw_command(req)
            cmd, params = parse_response(resp)
            if cmd == "register_success" and params.get("messageID") == str(msg_id):
                print(f"Пользователь {username} успешно зарегистрирован.")
                return True
            else:
                error = params.get("error", "Неизвестная ошибка")
                print(f"Ошибка регистрации: {error}")
                return False
        except Exception as e:
            print(f"Ошибка связи: {e}")
            return False

    def authenticate(self, username, password) -> bool:
        """Аутентификация пользователя. Получение интервала от сервера."""
        if self.authenticated:
            print("Уже аутентифицированы.")
            return True
        if not self.sock and not self.connect():
            print("Не удалось подключиться к серверу.")
            return False
        msg_id = generate_message_id()
        pwd_hash = hash_password(password)
        req = f'auth messageID: {msg_id} username: "{username}" password_hash: "{pwd_hash}"'
        try:
            resp = self._send_raw_command(req)
            cmd, params = parse_response(resp)
            if cmd == "auth_success" and params.get("messageID") == str(msg_id):
                self.authenticated = True
                self.username = username
                self.password_hash = pwd_hash
                if "interval" in params:
                    try:
                        interval_sec = float(params["interval"])
                        self.send_interval = int(interval_sec * 1000)
                        print(f"Аутентификация успешна. Интервал отправки: {interval_sec:.2f} с")
                    except ValueError:
                        print(f"Аутентификация успешна (интервал не распознан, оставлен {self.send_interval} мс)")
                else:
                    print("Аутентификация успешна (интервал по умолчанию).")
                print(f"Добро пожаловать, {username}!")
                return True
            else:
                error = params.get("error", "Неверный логин или пароль")
                print(f"Ошибка аутентификации: {error}")
                return False
        except Exception as e:
            print(f"Ошибка связи: {e}")
            self._close_socket()
            return False

    def send_data_once(self, hex_string: str) -> bool:
        """Отправить одну последовательность байт (hex-строка)."""
        if not self.authenticated:
            print("Необходимо сначала аутентифицироваться.")
            return False
        try:
            raw = bytes.fromhex(hex_string)
        except ValueError:
            print("Неверный формат hex-строки.")
            return False

        if not self.ensure_connection_and_auth():
            print("Нет соединения с сервером или не удалось аутентифицироваться.")
            return False

        msg_id = generate_message_id()
        length = len(raw)
        req = f'data messageID: {msg_id} length: {length} data: "{hex_string}"'
        try:
            resp = self._send_raw_command(req)
            cmd, params = parse_response(resp)
            if cmd == "data_success" and params.get("messageID") == str(msg_id):
                stored = params.get("bytes_stored", "0")
                print(f"Данные приняты, сохранено {stored} байт.")
                return True
            elif cmd == "data_error_buffer_full":
                message = params.get("message", "")
                print(f"Сервер сообщает: {message}")
                match = re.search(r"increase interval to (\d+) ms", message)
                if match:
                    new_interval = int(match.group(1))
                    self.send_interval = new_interval
                    print(f"Интервал отправки изменён на {self.send_interval} мс")
                return False
            else:
                print(f"Неожиданный ответ: {resp}")
                return False
        except Exception as e:
            print(f"Ошибка при отправке: {e}")
            self.authenticated = False
            self._close_socket()
            return False

    def disconnect(self) -> bool:
        """
        Отправить команду disconnect для корректного закрытия соединения.
        Возвращает True, если сервер подтвердил.
        """
        if not self.sock:
            return True
        msg_id = generate_message_id()
        req = f'disconnect messageID: {msg_id}'
        try:
            resp = self._send_raw_command(req, timeout=1.0)
            cmd, params = parse_response(resp)
            if cmd == "disconnect_success" and params.get("messageID") == str(msg_id):
                print("Соединение закрыто по протоколу.")
                return True
            else:
                print("Сервер не подтвердил disconnect, закрываем сокет.")
                return False
        except Exception:
            # Если не дождались ответа, просто закрываем сокет
            return False
        finally:
            self._close_socket()

    # ------------------- Периодическая отправка -------------------
    def periodic_send_worker(self, hex_string: str):
        while self.running:
            if not self.authenticated or not self.sock:
                print("Потеря соединения. Ожидание восстановления сервера...")
                while self.running and (not self.authenticated or not self.sock):
                    if self.connect() and self._reauth():
                        print("Соединение восстановлено. Возобновление отправки.")
                        break
                    else:
                        time.sleep(2)
                if not self.running:
                    break

            success = self.send_data_once(hex_string)
            if not success:
                time.sleep(1)
                continue
            time.sleep(self.send_interval / 1000.0)

        print("Периодическая отправка остановлена.")

    def start_sending(self, hex_string: str):
        if not self.authenticated:
            print("Сначала выполните аутентификацию (команда auth).")
            return
        if self.send_thread and self.send_thread.is_alive():
            print("Отправка уже запущена.")
            return
        self.running = True
        self.send_thread = threading.Thread(target=self.periodic_send_worker,
                                            args=(hex_string,), daemon=True)
        self.send_thread.start()
        print(f"Начата периодическая отправка с интервалом {self.send_interval} мс.")

    def stop_sending(self):
        self.running = False
        if self.send_thread:
            self.send_thread.join(timeout=1.0)
        print("Отправка остановлена.")

    def close(self):
        """Корректное закрытие соединения с отправкой disconnect."""
        self.stop_sending()
        self.disconnect()          # отправляем протокольный disconnect
        print("Соединение закрыто.")


# ------------------- Интерактивный режим -------------------
def interactive_mode(client: Client):
    print("\nДоступные команды:")
    print("  register <login> <password>   - регистрация")
    print("  auth <login> <password>       - аутентификация")
    print("  send <hex>                    - отправить один раз")
    print("  start <hex>                   - начать периодическую отправку")
    print("  stop                          - остановить периодическую отправку")
    print("  quit                          - выход")
    while True:
        try:
            cmd_line = input("> ").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split(maxsplit=1)
            cmd = parts[0].lower()
            if cmd == "quit":
                break
            elif cmd == "register" and len(parts) == 2:
                args = parts[1].split()
                if len(args) == 2:
                    client.register(args[0], args[1])
                else:
                    print("Формат: register login password")
            elif cmd == "auth" and len(parts) == 2:
                args = parts[1].split()
                if len(args) == 2:
                    client.authenticate(args[0], args[1])
                else:
                    print("Формат: auth login password")
            elif cmd == "send" and len(parts) == 2:
                client.send_data_once(parts[1])
            elif cmd == "start" and len(parts) == 2:
                client.start_sending(parts[1])
            elif cmd == "stop":
                client.stop_sending()
            else:
                print("Неверная команда.")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Ошибка: {e}")


def main():
    parser = argparse.ArgumentParser(description="Клиент для обмена байтами")
    parser.add_argument("--host", default="127.0.0.1", help="Сервер")
    parser.add_argument("--port", type=int, default=8888, help="Порт")
    parser.add_argument("--register", nargs=2, metavar=("LOGIN", "PASSWORD"),
                        help="Зарегистрироваться и выйти")
    parser.add_argument("--auth", nargs=2, metavar=("LOGIN", "PASSWORD"),
                        help="Аутентифицироваться и перейти в интерактивный режим")
    args = parser.parse_args()

    client = Client(args.host, args.port)
    if not client.connect():
        print("Не удалось подключиться к серверу при запуске.")
    else:
        print("Подключение установлено.")

    if args.register:
        client.register(args.register[0], args.register[1])
        client.close()
        return

    if args.auth:
        if client.authenticate(args.auth[0], args.auth[1]):
            interactive_mode(client)
        client.close()
        return

    interactive_mode(client)
    client.close()


if __name__ == "__main__":
    main()
