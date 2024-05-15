#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Emilio Mendoza Reyes
import datetime
import os
import argparse
import base64
import sqlite3
import fcntl
from abc import ABC, abstractmethod

import tqdm
import multiprocessing
import lzma
from sys import exit
from typing import AnyStr, List
from dataclasses import dataclass

# CRYPTOGRAPHY

from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC

# DEFAULTS/CONSTS
DEF_DELETE_TIMER_SECS: int \
	= 60 * 60 * 24 * 7  # 1 week
DEF_BASE_PATH: AnyStr \
	= os.path.expanduser('~/.backup_system/')

DEF_PATHS_TO_BACKUP: List[AnyStr] = [
	os.path.expanduser('~'),
]
DEF_PATHS_TO_EXCLUDE: List[AnyStr] = [
	'\\BACKUP_SYSTEM_MOUNT'
]
MOUNT_CMD: str = 'sshfs' if os.system('command -v sshfs > /dev/null') == 0 else exit('sshfs not found')
UMOUNT_CMD: str = 'fusermount3 -u' if os.system('command -v fusermount3 > /dev/null') == 0 else 'fusermount -u'

# SQL ENTRIES
CREATE_MAIN_TABLE: str = '''
CREATE TABLE IF NOT EXISTS FILES (
local_path TEXT PRIMARY KEY,
remote_path TEXT,
folder BOOLEAN,
deleted BOOLEAN,
deleted_at INTEGER,
uploaded_at INTEGER,
iv BLOB, 
sha512 BLOB,
size INTEGER,
permissions INTEGER,
compression TEXT,
compressed_size INTEGER)
'''
CREATE_VARS_TABLE: str = '''
CREATE TABLE IF NOT EXISTS VARS (
key TEXT PRIMARY KEY,
value TEXT)
'''
SET_SEPERATOR: str = '''
INSERT OR IGNORE INTO VARS (key, value) VALUES ('SEPERATOR', ?)
'''
GET_SEPERATOR: str = '''
SELECT value FROM VARS WHERE key = 'SEPERATOR'
'''
GET_TOP_LEVEL: str = '''
SELECT * FROM FILES WHERE local_path like ? || '%' AND local_path NOT LIKE ? || '%' || ? || '_%'
'''
GET_ALL_IN_DIR_RECURSIVE: str = '''
SELECT * FROM FILES WHERE local_path like ? || '_%'
'''


# Helper Functions
def bytes_to_human(size: int) -> AnyStr:
	for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
		if size < 1024:
			return f'{size:.2f} {unit}'
		size /= 1024
	return f'{size:.2f} PB'


def sha512_str(s: AnyStr) -> bytes:
	digest = hashes.Hash(hashes.SHA512())
	digest.update(s.encode('utf-8'))
	return digest.finalize()


def sha512_file(file: AnyStr) -> bytes:
	digest = hashes.Hash(hashes.SHA512())
	with open(file, 'rb') as f:
		while True:
			chunk = f.read(1024)
			if not chunk:
				break
			digest.update(chunk)
	return digest.finalize()


def epoch_to_datetime(epoch: int) -> AnyStr:
	return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d_%H:%M:%S')


# get hex string from bytes
def hash_to_str(h: bytes) -> AnyStr:
	return ''.join(f'{b:02x}' for b in h)


@dataclass
class FILE:
	local_path: AnyStr
	remote_path: AnyStr
	folder: bool
	deleted: bool
	deleted_at: int
	uploaded_at: int
	iv: bytes
	sha512: bytes
	size: int
	permissions: int
	compression: AnyStr
	compressed_size: int

	def str(self):
		return f'[{'DIR' if self.folder else 'FIL'}] {self.local_path} | {bytes_to_human(self.size)}'

	def str_v(self):
		verbose_name = \
			f'[{'DIR' if self.folder else 'FIL'}]: {self.local_path} \n' \
			f'SIZE: {bytes_to_human(self.size)}\n' \
			f'PERMISSIONS: {self.permissions}\n' \
			f'DATE UPLOADED: {epoch_to_datetime(self.uploaded_at)}\n' \
			f'DATE DELETED: {epoch_to_datetime(self.deleted_at)}\n' if self.deleted else '' \
			                                                                             f'HASH: {self.iv}\n'


# Compressors
class Compressor(ABC):
	@abstractmethod
	def __init__(self, decompress: bool):
		pass

	@abstractmethod
	def compress(self, data: bytes) -> bytes:
		pass

	@abstractmethod
	def decompress(self, data: bytes) -> bytes:
		pass

	@abstractmethod
	def finalize(self) -> bytes:
		pass


class CompressorNone(Compressor):
	def __init__(self, decompress: bool):
		pass

	def compress(self, data: bytes) -> bytes:
		return data

	def decompress(self, data: bytes) -> bytes:
		return data

	def finalize(self) -> bytes:
		return b''


class XZCompressor(Compressor):
	_decompress: bool

	def __init__(self, decompress: bool):
		self._decompress = decompress
		self.ctx = lzma.LZMADecompressor() if decompress else lzma.LZMACompressor()

	def compress(self, data: bytes) -> bytes:
		return self.ctx.compress(data)

	def decompress(self, data: bytes) -> bytes:
		return self.ctx.decompress(data)

	def finalize(self) -> bytes:
		if self._decompress:
			return b''
		return self.ctx.flush()


NAME_TO_COMPRESSOR = {
	'none': CompressorNone,
	'xz': XZCompressor
}

# ARGUMENT PARSING
ADDITIONAL_INFO_LINE = '''
Additional Notes: 
- Each file is individually encrypted with AES256 
- The iv of each file is stored in the metadata database 
- The database is also encrypted but the iv is placed in a separate file and in plane text 
- The options `-e` and `-d` are for manual file encryption and decryption and the IV-Len is NOT stored in the db. 
- The following special paths can be used: 
	\\BASE_PATH: The base path of the backup system (default: ~/.backup_system/) 
	\\KEY_PATH: The path to the symmetric key (default: ~/.backup_system/aes256_key.priv) 
	\\MOUNT_PATH: The path where the remote storage is mounted (default: ~/.backup_system/mount/) 
	\\METADATA_PATH: The path to the metadata database (default: ~/.backup_system/METADATA-BACKUP.sqlite3) 
	\\METADATA_IV_PATH: The path to the metadata database iv (default: ~/.backup_system/meta_data_iv) 
- The metadata database is used to keep track of the files and their metadata 
- By default, deleted files will take 1 week to be deleted off the remote 
- By default, files that have been modified will have the string '.modified<TIMESTAMP>' appended to  
  the old filename in the db and will have the old version deleted after 1 week. 
- Passing 'none' to --ssh will result in no remote storage being used.
- IV-Len is the IV followed by the size of the file in bytes. (16 bytes IV + 8 bytes big endian size)
- The `-c` option takes one of the following: none, xz
Author: Emilio Mendoza Reyes 
'''

parser = argparse.ArgumentParser(prog='backup-system',
                                 description='Backup system to remote storage, encrypting each file with AES256',
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=ADDITIONAL_INFO_LINE)
parser.add_argument('-g', '--generate-key', action='store_true', help='Generate a new symmetric key')
parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
parser.add_argument('-t', '--threads', type=int, help='Number of threads to use', default=multiprocessing.cpu_count())
parser.add_argument('-c', '--compress', type=str, help='Compress files before encrypting', default='none')
parser.add_argument('--base-path', type=str, help='Base path for the db and mount dir.', default=DEF_BASE_PATH)
parser.add_argument('--delete-timer-secs', type=int, help='Delete timer in seconds', default=DEF_DELETE_TIMER_SECS)
parser.add_argument('-e', '--encrypt', type=str, nargs=2,
                    metavar=('<in-path>', '<out-path>'),
                    help='Encrypt file.')
parser.add_argument('-d', '--decrypt', type=str, nargs=3,
                    metavar=('<in-path>', '<out-path>', '<IV-Len>'),
                    help='Decrypt file.')
parser.add_argument('-b', '--backup', action='store_true',
                    help='Backup system to remote storage, implies -p')
parser.add_argument('-r', '--restore', type=str, nargs='*',
                    help='Restore system from remote storage (optional: restore specific paths)')
parser.add_argument('-p', '--purge', action='store_true',
                    help='Purge old deleted files from remote storage')
parser.add_argument('-s', '--ssh', type=str,
                    help='SSH connection string. Required by r/b/p. e.g. user@host:/path/to/storage')
parser.add_argument('--delete_timer', type=int, help='Delete timer in seconds', default=DEF_DELETE_TIMER_SECS)
parser.add_argument('--paths_to_backup', type=str, nargs='*', help='Paths to backup', default=DEF_PATHS_TO_BACKUP)
parser.add_argument('--paths_to_exclude', type=str, nargs='*', help='Paths to exclude', default=DEF_PATHS_TO_EXCLUDE)

# GLOBALS
BASE_PATH: AnyStr | None = None
SEPERATOR: AnyStr | None = None
KEY_PATH: AnyStr | None = None
MOUNT_PATH: AnyStr | None = None
METADATA_PATH: AnyStr | None = None
METADATA_IV_PATH: AnyStr | None = None
PATHS_TO_BACKUP: AnyStr | None = None
PATHS_TO_EXCLUDE: AnyStr | None = None
SERVER: AnyStr | None = None
SQLITE_CONNECTION: sqlite3.Connection | None = None
DELETE_TIMER_SECS: int | None = None
THREADS: int | None = None
COMPRESSION_STR: AnyStr | None = None

vprint: callable = lambda *a, **k: None
mutex = multiprocessing.Lock()
queue = multiprocessing.Queue()


def wprint(*nargs, **kwargs):
	with mutex:
		curr_time = datetime.datetime.now().strftime('%H:%M:%S')
		print(f'[WARN {curr_time}]', *nargs, **kwargs)


def get_flock():
	lock_file = os.path.join(BASE_PATH, 'lock')
	lock = open(lock_file, 'w')
	try:
		fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except IOError | OSError:
		exit('Another instance is already running. Exiting...')


def encrypt_file(file: FILE, iv: bytes, key: bytes) -> int:
	cipher = Cipher(AES256(key), CBC(iv))
	compressor = NAME_TO_COMPRESSOR[file.compression](False)
	encryptor = cipher.encryptor()
	encrypted = 0
	with open(file.local_path, 'rb') as f, open(file.remote_path, 'wb') as o:
		# Read file in chunks
		while True:
			chunk = f.read(1024)
			if not chunk:
				break
			chunk = compressor.compress(chunk)
			encrypted += len(chunk)
			o.write(encryptor.update(chunk))
		# Finalize compression
		chunk = compressor.finalize()
		encrypted += len(chunk)
		# Pad file to 16 bytes
		if encrypted % 16 != 0:
			pad = os.urandom(16 - (encrypted % 16))
			chunk += pad
		o.write(encryptor.update(chunk))
		# Finalize encryption
		o.write(encryptor.finalize())
		return encrypted


def decrypt_file(file: FILE, iv: bytes, key: bytes) -> None:
	cipher = Cipher(AES256(key), CBC(iv))
	decompressor = NAME_TO_COMPRESSOR[file.compression](True)
	decryptor = cipher.decryptor()
	digest = hashes.Hash(hashes.SHA512())
	decrypted = 0
	with open(file.remote_path, 'rb') as f, open(file.local_path, 'wb') as o:
		# Read file in chunks
		while True:
			chunk = f.read(1024)
			if not chunk:
				break
			chunk = decryptor.update(chunk)[:(file.compressed_size - decrypted)]
			decrypted += len(chunk)
			chunk = decompressor.decompress(chunk)
			digest.update(chunk)
			o.write(chunk)
		# Finalize decompression
		chunk = decryptor.finalize()[:(file.compressed_size - decrypted)]
		if chunk:
			chunk = decompressor.decompress(chunk)
			digest.update(chunk)
			o.write(chunk)
			chunk = decompressor.finalize()
			digest.update(chunk)
			o.write(chunk)
		f_hash = digest.finalize()
		if file.sha512 != b'' and file.sha512 != f_hash:
			wprint(f'Hash mismatch for {file.local_path}, Might be corrupted')
		vprint(f'Decrypted {file.remote_path} to {file.local_path}\n\tHash: {hash_to_str(f_hash)}')


def generate_key():
	print('Generating a new AES256 symmetric key...')
	key = os.urandom(32)
	key_b64 = base64.b64encode(key).decode('utf-8')
	print(f'Key: {key_b64}\nWRITE THIS DOWN!')
	if not os.path.exists(KEY_PATH):
		with open(KEY_PATH, 'w', encoding='utf-8') as f:
			f.write(key_b64)
		os.chmod(KEY_PATH, 0o600)
		print(f'Key saved to {KEY_PATH}')
	else:
		print(f'{KEY_PATH} already exists. Not overwriting.')


def mount_remote_storage():
	if SERVER == 'none':
		return
	print(f'Mounting {SERVER}...')
	if not os.path.exists(MOUNT_PATH):
		os.makedirs(MOUNT_PATH)
	ret = os.system(f'{MOUNT_CMD} {SERVER} {MOUNT_PATH}')
	if ret != 0:
		exit('Failed to mount remote storage')
	print(f'Mounted at {MOUNT_PATH}')


def unmount_remote_storage():
	if SERVER == 'none':
		return
	print('Unmounting remote storage...')
	ret = os.system(f'{UMOUNT_CMD} {MOUNT_PATH}')
	if ret != 0:
		exit('Failed to unmount remote storage')
	print('Unmounted.')


def exit_post_mount(status: int | str):
	unmount_remote_storage()
	exit(status)


def get_key() -> bytes:
	print('Loading symmetric key...')
	if not os.path.exists(KEY_PATH):
		exit(f'{KEY_PATH} does not exist. Generate a key first.')
	with open(KEY_PATH, 'r', encoding='utf-8') as f:
		key = f.read()
	key = base64.b64decode(key)
	return key


def encrypt_file_op(info: List[AnyStr]):
	key = get_key()
	iv = os.urandom(16)
	f = FILE(get_real_path(info[0]), get_real_path(info[1]), False, False, 0, 0, iv, b'', 0, 0, COMPRESSION_STR, 0)
	f.compressed_size = encrypt_file(f, iv, key)
	iv_and_size = iv + f.compressed_size.to_bytes(8, 'big')
	print(f'Generated IV-Len: {base64.b64encode(iv_and_size).decode("utf-8")}\nYou need this to decrypt the file.')
	print(f'Encrypted {info[0]} as {info[1]}')


def decrypt_file_op(info: List[AnyStr]):
	key = get_key()
	iv_and_size = base64.b64decode(info[2])
	iv = iv_and_size[:16]
	size = int.from_bytes(iv_and_size[-8:], 'big')
	f = FILE(get_real_path(info[1]), get_real_path(info[0]), False, False, 0, 0, iv, b'', 0, 0, COMPRESSION_STR, size)
	decrypt_file(f, iv, key)
	print(f'Decrypted {info[0]} from {info[1]}')


def purge_system():
	pass


def backup_system():
	print('Backing up system...')
	mount_remote_storage()
	key = get_key()


def replace_special_path(path: AnyStr) -> AnyStr:
	if path.startswith('\\BASE_PATH'):
		return path.replace('\\BASE_PATH', BASE_PATH + os.sep)
	if path.startswith('\\KEY_PATH'):
		return path.replace('\\KEY_PATH', KEY_PATH + os.sep)
	if path.startswith('\\MOUNT_PATH'):
		return path.replace('\\MOUNT_PATH', MOUNT_PATH + os.sep)
	if path.startswith('\\METADATA_PATH'):
		return path.replace('\\METADATA_PATH', METADATA_PATH + os.sep)
	if path.startswith('\\METADATA_IV_PATH'):
		return path.replace('\\METADATA_IV_PATH', METADATA_IV_PATH + os.sep)
	return path


def get_real_path(path: AnyStr) -> AnyStr:
	path = replace_special_path(path)
	path = os.path.expanduser(path)
	path = os.path.abspath(path)
	return path


def prompt_option(options: List[str]) -> int:
	for i, option in enumerate(options):
		print(f'[{i}] {option}')
	while True:
		try:
			choice = int(input('Enter choice: '))
			if choice < 0 or choice > len(options):
				raise ValueError
			return choice
		except ValueError:
			print('Invalid choice. Try again.')


def prompt_options(options: List[str]) -> List[int]:
	choices = []
	for i, option in enumerate(options):
		print(f'[{i}] {option}')
	while True:
		try:
			choice = input('Enter choices separated by commas: ')
			choices = [int(c) for c in choice.split(',')]
			if any([c < 0 or c > len(options) for c in choices]):
				raise ValueError
			return choices
		except ValueError:
			print('Invalid choice. Try again.')


def prompt_files(files: List[FILE], verb_prompt: bool = False, only_one=False) -> List[FILE] | FILE:
	files_str = [f.str_v() if verb_prompt else f.str() for f in files]
	options = ['[OPT] Verbose Info' if not verb_prompt else '[OPT] Simple'] + files_str
	if only_one:
		choice = prompt_option(options)
		if choice == 0:
			return prompt_files(files, not verb_prompt, only_one=True)
		return files[choice - 1]

	choices = prompt_options(options)
	if 0 in choices:
		return prompt_files(files, not verb_prompt)
	return [files[i - 1] for i in choices]


def expand_path(file: FILE) -> List[FILE]:
	if file.folder:
		cursor = SQLITE_CONNECTION.execute(GET_ALL_IN_DIR_RECURSIVE, (file.local_path,))
		results = cursor.fetchall()
		if results is None:
			wprint(f'No files found in {file.local_path}')
			return []
		files = [FILE(*r) for r in results]
		vprint(f'Found {len(files)} files in {file.local_path}')
		return files
	return [file]


def restore_file(file: FILE, key: bytes):
	os.makedirs(os.path.dirname(file.local_path), exist_ok=True)
	if file.folder:
		os.makedirs(file.local_path, exist_ok=True)
		os.chmod(file.local_path, file.permissions)
		return
	while os.path.exists(file.local_path):
		wprint('File already exists. Appending .restored')
		file.local_path += '.restored'
	try:
		decrypt_file(file, file.iv, key)
		os.chmod(file.local_path, file.permissions)
		vprint(f'Restored {file.local_path}')
	except Exception as e:
		wprint(f'Failed to decrypt {file.local_path}. {e}')
		return


def done_callback():
	queue.put(1)


def restore_system(paths: List[AnyStr]):
	key = get_key()
	for i, path in enumerate(paths):
		paths[i] = get_real_path(path)
	print('Restoring system...')
	# Find all files in the metadata database
	files_to_restore = {}
	for path in paths:
		cursor = SQLITE_CONNECTION.execute(GET_TOP_LEVEL, (path, path, SEPERATOR))
		results = cursor.fetchall()
		if results is None:
			wprint(f'File/dir {path} not found in metadata database')
			continue
		files = [FILE(*r) for r in results]
		if len(results) > 1:
			print(f'Multiple valid entries found for {path}. Choose which:')
			files = prompt_files(files, only_one=False)
		actual_files = []
		for file in files:
			actual_files += expand_path(file)
		for file in actual_files:
			if file.local_path in files_to_restore:
				vprint(f'File {file.local_path} already in restore list')
				continue
			vprint(f'Adding {file.local_path} to restore list')
			files_to_restore[file.local_path] = file
	mount_remote_storage()
	total = len(files_to_restore.values())
	with multiprocessing.Pool(THREADS) as pool, tqdm.tqdm(total=total, unit='files') as bar:
		mp_args = [(file, key) for file in files_to_restore.values()]
		pool.starmap_async(restore_file, args, callback=done_callback)
		counter = 0
		while counter < total:
			queue.get()
			counter += 1
			with mutex:
				bar.update(1)


def parse_paths():
	# Generic Paths
	global PATHS_TO_BACKUP, PATHS_TO_EXCLUDE
	# Named Paths
	global BASE_PATH, KEY_PATH, MOUNT_PATH, METADATA_PATH, METADATA_IV_PATH, SQLITE_CONNECTION, \
		DELETE_TIMER_SECS, SERVER, THREADS, COMPRESSION_STR

	DELETE_TIMER_SECS = args.delete_timer_secs
	SERVER = args.ssh
	THREADS = args.threads
	COMPRESSION_STR = args.compress
	if COMPRESSION_STR not in NAME_TO_COMPRESSOR:
		exit('Invalid compression type')

	# Expand paths
	BASE_PATH = args.base_path
	KEY_PATH = os.path.join(BASE_PATH, 'aes256_key.priv')
	MOUNT_PATH = os.path.join(BASE_PATH, 'mount/')
	METADATA_PATH = os.path.join(BASE_PATH, 'METADATA-BACKUP.sqlite3')
	METADATA_IV_PATH = os.path.join(BASE_PATH, 'meta_data_iv')
	PATHS_TO_BACKUP = args.paths_to_backup
	PATHS_TO_EXCLUDE = args.paths_to_exclude

	BASE_PATH = get_real_path(BASE_PATH)
	KEY_PATH = get_real_path(KEY_PATH)
	MOUNT_PATH = get_real_path(MOUNT_PATH)
	METADATA_PATH = get_real_path(METADATA_PATH)
	METADATA_IV_PATH = get_real_path(METADATA_IV_PATH)

	# Replace special paths
	for i, path in enumerate(PATHS_TO_BACKUP):
		PATHS_TO_BACKUP[i] = get_real_path(path)

	# Expand paths
	for i, path in enumerate(PATHS_TO_BACKUP):
		PATHS_TO_BACKUP[i] = get_real_path(path)


def vprint_func(*nargs, **kwargs):
	with mutex:
		curr_time = datetime.datetime.now().strftime('%H:%M:%S')
		print(f'[{curr_time}]', *nargs, **kwargs)


if __name__ == '__main__':
	args = parser.parse_args()
	parse_paths()

	operator_count = 0
	operator_count = operator_count + 1 if args.generate_key else operator_count
	operator_count = operator_count + 1 if args.backup else operator_count
	operator_count = operator_count + 1 if args.restore else operator_count
	operator_count = operator_count + 1 if args.purge else operator_count
	operator_count = operator_count + 1 if args.encrypt else operator_count
	operator_count = operator_count + 1 if args.decrypt else operator_count
	if operator_count != 1:
		parser.print_help()
		exit('Exactly one operation must be specified')
	if args.verbose:
		vprint = vprint_func
	if args.generate_key or args.backup or args.restore or args.purge:
		# make dirs if they don't exist
		os.makedirs(BASE_PATH, exist_ok=True, mode=0o700)
		SQLITE_CONNECTION = sqlite3.connect(METADATA_PATH)
		SQLITE_CONNECTION.execute(CREATE_MAIN_TABLE)
		SQLITE_CONNECTION.execute(CREATE_VARS_TABLE)
		SQLITE_CONNECTION.execute(SET_SEPERATOR, (os.sep,))
		SEPERATOR = SQLITE_CONNECTION.execute(GET_SEPERATOR).fetchone()[0]
		get_flock()
	if args.generate_key:
		generate_key()
	if args.backup:
		backup_system()
	if args.restore:
		restore_system(args.restore)
	if args.purge:
		purge_system()
	if args.encrypt:
		encrypt_file_op(args.encrypt)
	if args.decrypt:
		decrypt_file_op(args.decrypt)
else:
	exit('This module is not importable')
