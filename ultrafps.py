# UltraFPS (Ultra Fast File Share Protocol Secure)

import asyncio
import os
import sys
import zstandard as zstd
import argparse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import secrets
import subprocess
from KamuJpModern import KamuJpModern  # KamuJpModern をインポート

CHUNK_SIZE = 1024 * 1024 * 8  # 8MB
COMPRESSION_LEVEL = 3
KEY_LENGTH = 32  # AES-256
IV_LENGTH = 16
SALT_LENGTH = 16
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    """
    パスワードとソルトからAESキーを導出します。
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

class UltraFPS_Server:
    def __init__(self, host, port, shared_dir, encrypt=False, compress=False, password=None, logger=None):
        self.host = host
        self.port = port
        self.shared_dir = os.path.abspath(shared_dir)
        self.encrypt = encrypt
        self.compress = compress
        self.password = password
        self.logger = logger or KamuJpModern().modernLogging(process_name="Server")
        self.zstd_compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL) if self.compress else None
        self.zstd_decompressor = zstd.ZstdDecompressor() if self.compress else None
        self.key = None
        self.iv = None
        self.salt = None
        if self.encrypt:
            if not self.password:
                raise ValueError("Password is required for encryption.")
            self.salt = secrets.token_bytes(SALT_LENGTH)
            self.key = derive_key(self.password, self.salt)
            self.iv = secrets.token_bytes(IV_LENGTH)
            self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        self.logger.log(f"[CONNECTED] {addr}", "INFO")
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                command_line = data.decode().strip()
                if not command_line:
                    continue
                self.logger.log(f"[COMMAND] {command_line} from {addr}", "INFO")
                parts = command_line.split()
                command = parts[0].upper()
                if command == 'UPLOAD':
                    await self.handle_upload(reader, writer, parts[1:], addr)
                elif command == 'DOWNLOAD':
                    await self.handle_download(reader, writer, parts[1:], addr)
                elif command == 'LIST':
                    await self.handle_list(writer, parts[1:], addr)
                elif command == 'MKDIR':
                    await self.handle_mkdir(writer, parts[1:], addr)
                elif command == 'EDIT':
                    await self.handle_edit(writer, parts[1:], addr)
                else:
                    await self.send_response(writer, f"ERR Unknown command: {command}\n")
        except Exception as e:
            self.logger.log(f"[ERROR] {e} from {addr}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()
            self.logger.log(f"[DISCONNECTED] {addr}", "INFO")

    async def send_response(self, writer, message):
        writer.write(message.encode())
        await writer.drain()

    async def handle_upload(self, reader, writer, args, addr):
        if len(args) < 1:
            await self.send_response(writer, "ERR Missing file path for UPLOAD\n")
            return
        relative_path = args[0]
        save_path = os.path.abspath(os.path.join(self.shared_dir, relative_path))
        if not save_path.startswith(self.shared_dir):
            await self.send_response(writer, "ERR Invalid file path\n")
            return
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        # 受信するファイルサイズ
        try:
            size_data = await reader.readexactly(8)
            file_size = int.from_bytes(size_data, 'big')
        except asyncio.IncompleteReadError:
            await self.send_response(writer, "ERR Failed to read file size\n")
            return
        # プログレスバーの設定
        total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
        progress_bar = KamuJpModern().modernProgressBar(total=total_chunks, process_name="UPLOAD", process_color=34)
        progress_bar.start()

        # 受信ファイルデータ
        received = 0
        with open(save_path, 'wb') as f:
            while received < file_size:
                try:
                    # チャンクサイズを受信
                    chunk_size_data = await reader.readexactly(8)
                    chunk_size = int.from_bytes(chunk_size_data, 'big')
                    # チャンクデータを受信
                    chunk = await reader.readexactly(chunk_size)
                except asyncio.IncompleteReadError:
                    await self.send_response(writer, "ERR Failed to read chunk data\n")
                    progress_bar.finish()
                    return
                if self.encrypt:
                    chunk = self.decryptor.update(chunk)
                if self.compress:
                    chunk = self.zstd_decompressor.decompress(chunk)
                f.write(chunk)
                received += chunk_size
                progress_bar.update()
        if self.encrypt:
            try:
                final_chunk = self.decryptor.finalize()
                if final_chunk:
                    with open(save_path, 'ab') as f:
                        f.write(final_chunk)
            except Exception as e:
                self.logger.log(f"[ERROR] Finalize decryption failed: {e}", "ERROR")
        progress_bar.finish()
        await self.send_response(writer, "OK Upload successful\n")
        self.logger.log(f"[UPLOAD] {relative_path} from {addr}", "INFO")

    async def handle_download(self, reader, writer, args, addr):
        if len(args) < 1:
            await self.send_response(writer, "ERR Missing file path for DOWNLOAD\n")
            return
        relative_path = args[0]
        file_path = os.path.abspath(os.path.join(self.shared_dir, relative_path))
        if not file_path.startswith(self.shared_dir):
            await self.send_response(writer, "ERR Invalid file path\n")
            return
        if not os.path.isfile(file_path):
            await self.send_response(writer, "ERR File does not exist\n")
            return
        file_size = os.path.getsize(file_path)
        await self.send_response(writer, f"OK {file_size}\n")
        # プログレスバーの設定
        total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
        progress_bar = KamuJpModern().modernProgressBar(total=total_chunks, process_name="DOWNLOAD", process_color=34)
        progress_bar.start()
        progress_bar.notbusy()

        # 送信ファイルデータ
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                if self.compress:
                    chunk = self.zstd_compressor.compress(chunk)
                if self.encrypt:
                    chunk = self.encryptor.update(chunk)
                writer.write(len(chunk).to_bytes(8, 'big') + chunk)
                await writer.drain()
                progress_bar.update()
        if self.encrypt:
            try:
                final_chunk = self.encryptor.finalize()
                if final_chunk:
                    writer.write(len(final_chunk).to_bytes(8, 'big') + final_chunk)
                    await writer.drain()
            except Exception as e:
                self.logger.log(f"[ERROR] Finalize encryption failed: {e}", "ERROR")
        progress_bar.finish()
        self.logger.log(f"[DOWNLOAD] {relative_path} to {addr}", "INFO")

    async def handle_list(self, writer, args, addr):
        directory = args[0] if args else '.'
        list_path = os.path.abspath(os.path.join(self.shared_dir, directory))
        if not list_path.startswith(self.shared_dir):
            await self.send_response(writer, "ERR Invalid directory path\n")
            return
        if not os.path.isdir(list_path):
            await self.send_response(writer, "ERR Directory does not exist\n")
            return
        items = os.listdir(list_path)
        response = '\n'.join(items) + '\n'
        await self.send_response(writer, f"OK {len(response.encode())}\n")
        writer.write(response.encode())
        await writer.drain()
        self.logger.log(f"[LIST] {directory} to {addr}", "INFO")

    async def handle_mkdir(self, writer, args, addr):
        if len(args) < 1:
            await self.send_response(writer, "ERR Missing directory path for MKDIR\n")
            return
        directory = args[0]
        dir_path = os.path.abspath(os.path.join(self.shared_dir, directory))
        if not dir_path.startswith(self.shared_dir):
            await self.send_response(writer, "ERR Invalid directory path\n")
            return
        os.makedirs(dir_path, exist_ok=True)
        await self.send_response(writer, "OK Directory created\n")
        self.logger.log(f"[MKDIR] {directory} by {addr}", "INFO")

    async def handle_edit(self, writer, args, addr):
        if len(args) < 1:
            await self.send_response(writer, "ERR Missing file path for EDIT\n")
            return
        relative_path = args[0]
        file_path = os.path.abspath(os.path.join(self.shared_dir, relative_path))
        if not file_path.startswith(self.shared_dir):
            await self.send_response(writer, "ERR Invalid file path\n")
            return
        if not os.path.isfile(file_path):
            await self.send_response(writer, "ERR File does not exist\n")
            return
        await self.send_response(writer, "OK Opening editor\n")
        # EDIT機能はクライアント側で処理します
        self.logger.log(f"[EDIT] {relative_path} requested by {addr}", "INFO")
        await self.send_response(writer, "ERR EDIT not implemented on server\n")

    async def start_server(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        self.logger.log(f"[SERVER] Listening on {addrs}", "INFO")
        async with server:
            await server.serve_forever()

class UltraFPS_Client:
    def __init__(self, host, port, encrypt=False, compress=False, password=None, logger=None):
        self.host = host
        self.port = port
        self.encrypt = encrypt
        self.compress = compress
        self.password = password
        self.logger = logger or KamuJpModern().modernLogging(process_name="Client")
        self.zstd_compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL) if self.compress else None
        self.zstd_decompressor = zstd.ZstdDecompressor() if self.compress else None
        self.key = None
        self.iv = None
        self.salt = None
        if self.encrypt:
            if not self.password:
                raise ValueError("Password is required for encryption.")
            self.salt = secrets.token_bytes(SALT_LENGTH)
            self.key = derive_key(self.password, self.salt)
            self.iv = secrets.token_bytes(IV_LENGTH)
            self.cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()

    async def send_command(self, writer, command):
        writer.write((command + '\n').encode())
        await writer.drain()

    async def upload(self, relative_path, local_path):
        if not os.path.isfile(local_path):
            print(f"[ERR] Local file '{local_path}' does not exist.")
            return
        file_size = os.path.getsize(local_path)
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            await self.send_command(writer, f"UPLOAD {relative_path}")
            # 送信ファイルサイズ
            writer.write(file_size.to_bytes(8, 'big'))
            await writer.drain()
            # プログレスバーの設定
            total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
            progress_bar = KamuJpModern().modernProgressBar(total=total_chunks, process_name="UPLOAD", process_color=32)
            progress_bar.start()
            progress_bar.notbusy()

            # 送信ファイルデータ
            with open(local_path, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    if self.compress:
                        chunk = self.zstd_compressor.compress(chunk)
                    if self.encrypt:
                        chunk = self.encryptor.update(chunk)
                    writer.write(len(chunk).to_bytes(8, 'big') + chunk)
                    await writer.drain()
                    progress_bar.update()
            if self.encrypt:
                try:
                    final_chunk = self.encryptor.finalize()
                    if final_chunk:
                        writer.write(len(final_chunk).to_bytes(8, 'big') + final_chunk)
                        await writer.drain()
                except Exception as e:
                    self.logger.log(f"[ERROR] Finalize encryption failed: {e}", "ERROR")
            progress_bar.finish()
            # サーバーからのレスポンス
            response = await reader.readline()
            print(response.decode().strip())
            self.logger.log(f"[UPLOAD] {relative_path} to server", "INFO")
        except Exception as e:
            self.logger.log(f"[ERROR] Upload failed: {e}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()

    async def download(self, relative_path, local_path):
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            await self.send_command(writer, f"DOWNLOAD {relative_path}")
            response = await reader.readline()
            if response.startswith(b"OK"):
                parts = response.decode().strip().split()
                if len(parts) < 2:
                    print("[ERR] Invalid response from server.")
                    return
                file_size = int(parts[1])
                received = 0
                # プログレスバーの設定
                total_chunks = file_size // CHUNK_SIZE + (1 if file_size % CHUNK_SIZE else 0)
                progress_bar = KamuJpModern().modernProgressBar(total=total_chunks, process_name="DOWNLOAD", process_color=32)
                progress_bar.start()

                with open(local_path, 'wb') as f:
                    while received < file_size:
                        try:
                            # 受信チャンクサイズ
                            chunk_size_data = await reader.readexactly(8)
                            chunk_size = int.from_bytes(chunk_size_data, 'big')
                            # 受信チャンクデータ
                            chunk = await reader.readexactly(chunk_size)
                        except asyncio.IncompleteReadError:
                            print("[ERR] Failed to read chunk data.")
                            progress_bar.finish()
                            return
                        if self.encrypt:
                            chunk = self.decryptor.update(chunk)
                        if self.compress:
                            chunk = self.zstd_decompressor.decompress(chunk)
                        f.write(chunk)
                        received += chunk_size
                        progress_bar.update()
                if self.encrypt:
                    try:
                        final_chunk = self.decryptor.finalize()
                        if final_chunk:
                            with open(local_path, 'ab') as f:
                                f.write(final_chunk)
                    except Exception as e:
                        self.logger.log(f"[ERROR] Finalize decryption failed: {e}", "ERROR")
                progress_bar.finish()
                print("[OK] Download successful.")
                self.logger.log(f"[DOWNLOAD] {relative_path} from server", "INFO")
            else:
                print(response.decode().strip())
        except Exception as e:
            self.logger.log(f"[ERROR] Download failed: {e}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()

    async def list_dir(self, directory='.'):
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            await self.send_command(writer, f"LIST {directory}")
            response = await reader.readline()
            if response.startswith(b"OK"):
                parts = response.decode().strip().split()
                if len(parts) < 2:
                    print("[ERR] Invalid response from server.")
                    return
                list_size = int(parts[1])
                listing = await reader.readexactly(list_size)
                print("[LIST]")
                print(listing.decode())
                self.logger.log(f"[LIST] {directory} from server", "INFO")
            else:
                print(response.decode().strip())
        except Exception as e:
            self.logger.log(f"[ERROR] List directory failed: {e}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()

    async def mkdir(self, directory):
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            await self.send_command(writer, f"MKDIR {directory}")
            response = await reader.readline()
            print(response.decode().strip())
            if response.startswith(b"OK"):
                self.logger.log(f"[MKDIR] {directory} on server", "INFO")
            else:
                self.logger.log(f"[MKDIR] {directory} failed: {response.decode().strip()}", "ERROR")
        except Exception as e:
            self.logger.log(f"[ERROR] Mkdir failed: {e}", "ERROR")
        finally:
            writer.close()
            await writer.wait_closed()

    async def edit(self, relative_path):
        # クライアント側でファイルをダウンロードし、エディタで編集後、再アップロードします
        local_temp = f".temp_edit_{os.path.basename(relative_path)}"
        await self.download(relative_path, local_temp)
        editor = os.getenv('EDITOR', 'nano')  # 環境変数EDITORが設定されていない場合はnanoを使用
        subprocess.call([editor, local_temp])
        await self.upload(relative_path, local_temp)
        os.remove(local_temp)
        print("[OK] Edited and uploaded the file.")
        self.logger.log(f"[EDIT] {relative_path} on server", "INFO")

    async def interactive(self):
        print("Welcome to UltraFPS Client!")
        print("Available commands: upload <remote_path> <local_path>, download <remote_path> <local_path>, list [directory], mkdir <directory>, edit <remote_path>, exit")
        while True:
            try:
                cmd = input("UltraFPS> ").strip().split()
            except EOFError:
                print("\n[WARN] Exiting UltraFPS Client.")
                break
            if not cmd:
                continue
            command = cmd[0].lower()
            if command == 'upload' and len(cmd) == 3:
                await self.upload(cmd[1], cmd[2])
            elif command == 'download' and len(cmd) == 3:
                await self.download(cmd[1], cmd[2])
            elif command == 'list':
                directory = cmd[1] if len(cmd) > 1 else '.'
                await self.list_dir(directory)
            elif command == 'mkdir' and len(cmd) == 2:
                await self.mkdir(cmd[1])
            elif command == 'edit' and len(cmd) == 2:
                await self.edit(cmd[1])
            elif command == 'exit':
                print("Exiting UltraFPS Client.")
                break
            else:
                print("Invalid command or arguments.")
                print("Available commands: upload <remote_path> <local_path>, download <remote_path> <local_path>, list [directory], mkdir <directory>, edit <remote_path>, exit")

async def main():
    parser = argparse.ArgumentParser(description="UltraFPS: Ultra Fast File Share Protocol Secure")
    subparsers = parser.add_subparsers(dest='mode', help='server/client')

    # サーバーモードの引数
    server_parser = subparsers.add_parser('server', help='Run in server mode')
    server_parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind')
    server_parser.add_argument('--port', type=int, default=4321, help='Port to bind')
    server_parser.add_argument('shared_dir', type=str, help='Directory to share')
    server_parser.add_argument('--compress', action='store_true', help='Enable compression')
    server_parser.add_argument('--password', type=str, help='Password for encryption (optional)')

    # クライアントモードの引数
    client_parser = subparsers.add_parser('client', help='Run in client mode')
    client_parser.add_argument('host', type=str, help='Server IP address')
    client_parser.add_argument('--port', type=int, default=4321, help='Server port')
    client_parser.add_argument('--compress', action='store_true', help='Enable compression')
    client_parser.add_argument('--password', type=str, help='Password for encryption (optional)')

    args = parser.parse_args()

    if args.mode == 'server':
        password = args.password
        encrypt = bool(password)
        server = UltraFPS_Server(
            host=args.host,
            port=args.port,
            shared_dir=args.shared_dir,
            encrypt=encrypt,
            compress=args.compress,
            password=password
        )
        await server.start_server()
    elif args.mode == 'client':
        password = args.password
        encrypt = bool(password)
        client = UltraFPS_Client(
            host=args.host,
            port=args.port,
            encrypt=encrypt,
            compress=args.compress,
            password=password
        )
        await client.interactive()
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[WARN] Exiting UltraFPS.")
