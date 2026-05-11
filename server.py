#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import time
import random
import datetime
import hashlib
import argparse
import logging
import re
import sys

# ------------------- Настройки по умолчанию -------------------
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 8888
DEFAULT_MAX_CLIENTS = 3
DEFAULT_BUFFER_SIZE = 1024        # байт
DEFAULT_DELAY_MIN = 1.0           # секунды
DEFAULT_DELAY_MAX = 5.0           # секунды
DEFAULT_INTERVAL_MS = 1000        # начальный интервал для клиента (мс)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("server.log", encoding='utf-8'), logging.StreamHandler()]
)
SESSION_LOG_FILE = "sessions.log"

# ------------------- Пользователи -------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()[:32]

def load_users(filename: str = "users.txt") -> dict:
    users = {}
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    login, pwd_hash = line.split(':', 1)
                    users[login] = pwd_hash
    except FileNotFoundError:
        users["admin"] = hash_password("admin")
        save_users(users, filename)
        logging.info(f"Создан {filename} с admin/admin")
    return users

def save_users(users: dict, filename: str = "users.txt"):
    with open(filename, 'w', encoding='utf-8') as f:
        for login, pwd_hash in users.items():
            f.write(f"{login}:{pwd_hash}\n")

def register_user(users: dict, login: str, password_hash: str, filename: str) -> bool:
    if login in users:
        return False
    users[login] = password_hash
    save_users(users, filename)
    return True

def authenticate_user(users: dict, login: str, password_hash: str) -> bool:
    return users.get(login) == password_hash

# ------------------- Буфер байт -------------------
class ByteBuffer:
    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        self.data = bytearray()
        self.lock = threading.Lock()

    def store(self, data: bytes) -> int:
        with self.lock:
            free = self.max_bytes - len(self.data)
            if free <= 0:
                return 0
            to_store = min(len(data), free)
            self.data.extend(data[:to_store])
            return to_store

    def get_contents(self) -> bytes:
        with self.lock:
            return bytes(self.data)

    def get_fill_percent(self) -> float:
        with self.lock:
            return (len(self.data) / self.max_bytes) * 100 if self.max_bytes > 0 else 0

    def clear(self):
        with self.lock:
            self.data.clear()

    def resize(self, new_max_bytes: int):
        with self.lock:
            self.max_bytes = new_max_bytes
            if len(self.data) > self.max_bytes:
                self.data = self.data[:self.max_bytes]

# ------------------- Поток вывода буфера -------------------
class BufferDisplayThread(threading.Thread):
    def __init__(self, buffer: ByteBuffer, server):
        super().__init__(daemon=True)
        self.buffer = buffer
        self.server = server
        self.running = True

    def run(self):
        while self.running:
            with self.server.delay_lock:
                dmin = self.server.delay_min
                dmax = self.server.delay_max
            time.sleep(random.uniform(dmin, dmax))
            if not self.running:
                break
            contents = self.buffer.get_contents()
            fill = self.buffer.get_fill_percent()
            print("\n" + "="*60)
            print(f"Буфер (заполнено {fill:.1f}%):")
            print(contents.hex() if contents else "(пусто)")
            print(f"Байт: {len(contents)}")
            print("="*60)
            logging.info(f"Вывод буфера: {len(contents)} байт, {fill:.1f}%")
            self.buffer.clear()

    def stop(self):
        self.running = False

# ------------------- Сессия клиента -------------------
class ClientSession:
    def __init__(self, conn, addr, data_buffer, users, users_file,
                 active_clients_counter, clients_lock, max_clients, server):
        self.conn = conn
        self.addr = addr
        self.data_buffer = data_buffer
        self.users = users
        self.users_file = users_file
        self.active_clients_counter = active_clients_counter
        self.clients_lock = clients_lock
        self.max_clients = max_clients
        self.server = server
        self.client_id = None
        self.username = None
        self.authenticated = False
        self.start_time = datetime.datetime.now()
        self.current_interval = DEFAULT_INTERVAL_MS
        self.running = True
        self.buffer = ""

    def log(self, msg):
        logging.info(f"Клиент {self.client_id or '?'} ({self.addr}): {msg}")

    def send_line(self, line: str):
        try:
            self.conn.sendall((line + '\n').encode('utf-8'))
        except Exception as e:
            self.log(f"Ошибка отправки: {e}")
            self.running = False

    def handle(self):
        self.log("Начало сессии")
        self.conn.settimeout(10.0)
        try:
            while self.running:
                try:
                    data = self.conn.recv(4096).decode('utf-8')
                    if not data:
                        break
                    self.buffer += data
                    while '\n' in self.buffer:
                        line, self.buffer = self.buffer.split('\n', 1)
                        line = line.strip()
                        if line:
                            self.process_command(line)
                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    break
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            self.close_session()

    def process_command(self, line: str):
        parts = line.split()
        if not parts:
            return
        command = parts[0]

        params = {}
        i = 1
        while i < len(parts):
            if ':' in parts[i]:
                key = parts[i].rstrip(':')
                if i+1 < len(parts):
                    val = parts[i+1]
                    if val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    params[key] = val
                    i += 2
                else:
                    i += 1
            else:
                i += 1

        msg_id = params.get('messageID', '?')

        # ---- Обработка команд ----
        if command == 'connection':
            if self.client_id is not None:
                self.send_line(f"connection_error messageID: {msg_id} error: \"Already connected\"")
                return
            new_client_id = params.get('clientID')
            if not new_client_id:
                self.send_line(f"connection_error messageID: {msg_id} error: \"Missing clientID\"")
                return
            with self.clients_lock:
                if self.active_clients_counter[0] >= self.max_clients:
                    self.send_line(f"connection_error messageID: {msg_id} error: \"Max clients limit reached\"")
                    self.running = False
                    return
                self.active_clients_counter[0] += 1
                self.client_id = new_client_id
            self.send_line(f"connection_success messageID: {msg_id}")
            self.log(f"Подключён, активных клиентов: {self.active_clients_counter[0]}")

        elif command == 'register':
            if self.client_id is None:
                self.send_line(f"register_error messageID: {msg_id} error: \"Not connected\"")
                return
            if self.authenticated:
                self.send_line(f"register_error messageID: {msg_id} error: \"Already authenticated\"")
                return
            username = params.get('username')
            pwd_hash = params.get('password_hash')
            if not username or not pwd_hash:
                self.send_line(f"register_error messageID: {msg_id} error: \"Missing fields\"")
                return
            if register_user(self.users, username, pwd_hash, self.users_file):
                self.send_line(f"register_success messageID: {msg_id}")
                self.log(f"Зарегистрирован {username}")
            else:
                self.send_line(f"register_error messageID: {msg_id} error: \"Username already exists\"")

        elif command == 'auth':
            if self.client_id is None:
                self.send_line(f"auth_error messageID: {msg_id} error: \"Not connected\"")
                return
            if self.authenticated:
                self.send_line(f"auth_error messageID: {msg_id} error: \"Already authenticated\"")
                return
            username = params.get('username')
            pwd_hash = params.get('password_hash')
            if not username or not pwd_hash:
                self.send_line(f"auth_error messageID: {msg_id} error: \"Missing fields\"")
                return
            if authenticate_user(self.users, username, pwd_hash):
                self.authenticated = True
                self.username = username
                interval_sec = self.current_interval / 1000.0
                self.send_line(f"auth_success messageID: {msg_id} interval: {interval_sec}")
                self.log(f"Аутентифицирован {username}, интервал {interval_sec:.2f} с")
            else:
                self.send_line(f"auth_error messageID: {msg_id} error: \"Invalid username or password\"")

        elif command == 'data':
            if not self.authenticated:
                self.send_line(f"data_error_not_auth messageID: {msg_id} error: \"Not authenticated\"")
                return
            hex_data = params.get('data', '')
            if not hex_data:
                self.send_line(f"data_error_buffer_full messageID: {msg_id} message: \"No data\"")
                return
            try:
                raw = bytes.fromhex(hex_data)
            except ValueError:
                self.send_line(f"data_error_buffer_full messageID: {msg_id} message: \"Invalid hex\"")
                return
            stored = self.data_buffer.store(raw)
            if stored == 0:
                self.current_interval += 500
                self.send_line(f"data_error_buffer_full messageID: {msg_id} message: \"Buffer full, increase interval to {self.current_interval} ms\"")
                self.log(f"Буфер полон, рекомендован интервал {self.current_interval} мс")
            else:
                self.send_line(f"data_success messageID: {msg_id} bytes_stored: {stored}")
                self.log(f"Сохранено {stored} байт (всего в буфере {len(self.data_buffer.data)}/{self.data_buffer.max_bytes})")

        elif command == 'disconnect':
            # Протокольное закрытие соединения
            self.send_line(f"disconnect_success messageID: {msg_id}")
            self.log(f"Получен disconnect, завершаем сессию")
            self.running = False

        elif command == 'quit':
            self.send_line("bye")
            self.running = False

        else:
            self.send_line(f"error unknown_command messageID: {msg_id} error: \"{command}\"")

    def close_session(self):
        end_time = datetime.datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        self.log(f"Сессия завершена, длительность {duration:.2f} сек")

        if self.username:
            with open(SESSION_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"SESSION: {self.username} started at {self.start_time.isoformat()} ended at {end_time.isoformat()} duration {duration:.2f}s\n")

        with self.clients_lock:
            if self.client_id is not None and self.active_clients_counter[0] > 0:
                self.active_clients_counter[0] -= 1
        try:
            self.conn.close()
        except:
            pass

# ------------------- Сервер -------------------
class Server:
    def __init__(self, host, port, max_clients, buffer_size, delay_min, delay_max):
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.buffer_size = buffer_size
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.delay_lock = threading.Lock()
        self.data_buffer = ByteBuffer(buffer_size)
        self.active_clients = [0]
        self.clients_lock = threading.Lock()
        self.users = load_users()
        self.users_file = "users.txt"
        self.socket = None
        self.running = True
        self.display_thread = BufferDisplayThread(self.data_buffer, self)

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(self.max_clients)
        logging.info(f"Сервер на {self.host}:{self.port}, буфер {self.buffer_size} байт, задержки вывода {self.delay_min}-{self.delay_max} с")
        self.display_thread.start()
        threading.Thread(target=self.admin_console, daemon=True).start()

        while self.running:
            try:
                self.socket.settimeout(1.0)
                conn, addr = self.socket.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logging.error(f"Accept ошибка: {e}")
                break
            session = ClientSession(conn, addr, self.data_buffer, self.users, self.users_file,
                                    self.active_clients, self.clients_lock, self.max_clients, self)
            thread = threading.Thread(target=session.handle, daemon=True)
            thread.start()
        self.stop()

    def admin_console(self):
        print("\nАдминистративная консоль активна. Команды:")
        print("  set_buffer_size <байт>    - изменить размер буфера")
        print("  set_delay_min <сек>       - изменить минимальную задержку вывода")
        print("  set_delay_max <сек>       - изменить максимальную задержку вывода")
        print("  help                      - показать справку")
        while self.running:
            try:
                cmd = sys.stdin.readline().strip()
                if not cmd:
                    continue
                if cmd.startswith("set_buffer_size"):
                    try:
                        new_size = int(cmd.split()[1])
                        if new_size < 1:
                            print("Размер должен быть положительным")
                            continue
                        self.data_buffer.resize(new_size)
                        logging.info(f"Размер буфера изменён на {new_size} байт")
                        print(f"[ADMIN] Буфер изменён: {new_size} байт")
                    except (IndexError, ValueError):
                        print("Использование: set_buffer_size <число>")
                elif cmd.startswith("set_delay_min"):
                    try:
                        new_dmin = float(cmd.split()[1])
                        if new_dmin < 0:
                            print("Задержка не может быть отрицательной")
                            continue
                        with self.delay_lock:
                            self.delay_min = new_dmin
                        logging.info(f"Минимальная задержка вывода изменена на {new_dmin} с")
                        print(f"[ADMIN] Минимальная задержка: {new_dmin} с")
                    except (IndexError, ValueError):
                        print("Использование: set_delay_min <секунды>")
                elif cmd.startswith("set_delay_max"):
                    try:
                        new_dmax = float(cmd.split()[1])
                        if new_dmax < 0:
                            print("Задержка не может быть отрицательной")
                            continue
                        with self.delay_lock:
                            self.delay_max = new_dmax
                        logging.info(f"Максимальная задержка вывода изменена на {new_dmax} с")
                        print(f"[ADMIN] Максимальная задержка: {new_dmax} с")
                    except (IndexError, ValueError):
                        print("Использование: set_delay_max <секунды>")
                elif cmd == "help":
                    print("Доступные команды: set_buffer_size, set_delay_min, set_delay_max")
                else:
                    print("Неизвестная команда. Введите help.")
            except EOFError:
                break
            except Exception as e:
                logging.error(f"Ошибка в админ-консоли: {e}")

    def stop(self):
        self.running = False
        self.display_thread.stop()
        if self.socket:
            self.socket.close()
        logging.info("Сервер остановлен")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--max-clients", type=int, default=DEFAULT_MAX_CLIENTS)
    parser.add_argument("--buffer-size", type=int, default=DEFAULT_BUFFER_SIZE)
    parser.add_argument("--delay-min", type=float, default=DEFAULT_DELAY_MIN)
    parser.add_argument("--delay-max", type=float, default=DEFAULT_DELAY_MAX)
    args = parser.parse_args()

    server = Server(args.host, args.port, args.max_clients, args.buffer_size,
                    args.delay_min, args.delay_max)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    main()
