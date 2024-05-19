#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Emilio Mendoza Reyes
import datetime
import os
import argparse
import base64
import sqlite3
import fcntl
import time
from abc import ABC, abstractmethod
from copy import copy
from io import TextIOWrapper

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
MAX_RETRIES = 10
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
SSHFS_OPTIONS: str = ('-o sshfs_sync -o max_conns=10 -o reconnect -o ServerAliveInterval=15 -o ServerAliveCountMax=3 '
                      '-o follow_symlinks')
MOUNT_CMD: str = f'sshfs {SSHFS_OPTIONS}' if os.system('command -v sshfs > /dev/null') == 0 else exit('sshfs not found')
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
SET_VAR: str = '''
INSERT OR IGNORE INTO VARS (key, value) VALUES (?, ?)
'''
GET_VAR: str = '''
SELECT value FROM VARS WHERE key = ?
'''
GET_TOP_LEVEL: str = '''
SELECT * FROM FILES WHERE local_path like ? || '%' AND local_path NOT LIKE ? || '%' || ? || '_%'
'''
GET_ALL_IN_DIR_RECURSIVE: str = '''
SELECT * FROM FILES WHERE local_path like ? || '_%'
'''
GET_SINGLE_FILE: str = '''
SELECT * FROM FILES WHERE local_path = ?
'''
GET_SINGLE_FILE_REMOTE: str = '''
SELECT * FROM FILES WHERE remote_path = ?
'''
INSERT_REPLACE: str = '''
REPLACE INTO FILES
(local_path, remote_path, folder, deleted, deleted_at, uploaded_at, iv, sha512, size, permissions, compression, compressed_size)
VALUES
(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
'''
INSERT: str = '''
INSERT INTO FILES
(local_path, remote_path, folder, deleted, deleted_at, uploaded_at, iv, sha512, size, permissions, compression, compressed_size)
VALUES
(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
'''
DELETE: str = '''
DELETE FROM FILES WHERE local_path = ?
'''
DELETE_FROM_REMOTE: str = '''
DELETE FROM FILES WHERE remote_path = ?
'''

GET_ALL_NAMES_COLUMN: str = '''
SELECT local_path FROM FILES WHERE ? = ?
'''

GET_ALL_COLUMN: str = '''
SELECT * FROM FILES WHERE ? = ?
'''

ADD_COLUMN: str = '''
ALTER TABLE FILES ADD COLUMN ? ?
'''

SET_ALL_IN_COLUMN: str = '''
UPDATE FILES SET ? = ?
'''
SET_IN_NAME: str = '''
UPDATE FILES SET ? = ? WHERE local_path = ?
'''


# Helper Functions
def bytes_to_human(size: int) -> AnyStr:
	for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
		if size < 1024:
			return f'{size:.2f} {unit}'
		size /= 1024
	return f'{size:.2f} PB'


def update_db_v0_v1():
	result = SQLITE_CONNECTION.execute(GET_VAR, ('VERSION',)).fetchone()
	if result is not None:
		return
	SQLITE_CONNECTION.execute(SET_VAR, ('VERSION', '1'))
	SQLITE_CONNECTION.execute(SET_VAR, ('UUID', os.urandom(16).hex()))
	SQLITE_CONNECTION.execute(ADD_COLUMN, ('uploading', 'BOOLEAN'))
	SQLITE_CONNECTION.execute(SET_ALL_IN_COLUMN, ('uploading', False))
	SQLITE_CONNECTION.commit()


def sha512_file(file: AnyStr) -> bytes:
	digest = hashes.Hash(hashes.SHA512())
	with open(file, 'rb') as f:
		while True:
			chunk = f.read(4096)
			if not chunk:
				break
			digest.update(chunk)
	return digest.finalize()


def epoch_to_datetime(epoch: int) -> AnyStr:
	return datetime.datetime.fromtimestamp(epoch).strftime('%Y-%m-%d_%H:%M:%S')


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
	uploading: bool

	def to_sql(self):
		return (
			self.local_path, self.remote_path, self.folder, self.deleted, self.deleted_at, self.uploaded_at, self.iv,
			self.sha512, self.size, self.permissions, self.compression, self.compressed_size, self.uploading)

	def str(self):
		return f'[{'DIR' if self.folder else 'FIL'}] {self.local_path} | {bytes_to_human(self.size)}'

	def str_v(self):
		verbose_name = f'[{'DIR' if self.folder else 'FIL'}]: {self.local_path} \n'
		verbose_name += f'SIZE: {bytes_to_human(self.size)}\n'
		verbose_name += f'PERMISSIONS: {oct(self.permissions)}\n'
		verbose_name += f'DATE UPLOADED: {epoch_to_datetime(self.uploaded_at)}'
		verbose_name += f'\nDATE DELETED: {epoch_to_datetime(self.deleted_at)}' if self.deleted else ''
		verbose_name += f'\nHASH: {self.sha512.hex()}' if self.sha512 != b'' else ''

		return verbose_name


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
	\\METADATA_IV_PATH: The path to the metadata database iv (default: ~/.backup_system/mount/meta_data_iv) 
- The metadata database is used to keep track of the files and their metadata 
- By default, deleted files will take 1 week to be deleted off the remote 
- By default, files that have been modified will have the string '.old<TIMESTAMP>' appended to  
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
parser.add_argument('--sha', action='store_true',
                    help='Use sha512 to check if file has been modified as opposed to mtime')
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
parser.add_argument('-s', '--ssh', type=str, default='none',
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
LOCK_FD: TextIOWrapper | None = None

vprint: callable = lambda *a, **k: None
mutex = multiprocessing.Lock()
file_mutex = multiprocessing.Lock()
db_mutex = multiprocessing.Lock()
queue = multiprocessing.Queue()


def wprint(*nargs, **kwargs):
	with mutex:
		curr_time = datetime.datetime.now().strftime('%H:%M:%S')
		print(f'[WARN {curr_time}]', *nargs, **kwargs)


def get_flock():
	global LOCK_FD
	lock_file = os.path.join(BASE_PATH, 'lock')
	LOCK_FD = open(lock_file, 'w')
	try:
		fcntl.flock(LOCK_FD, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except IOError | OSError:
		exit('Another instance is already running. Exiting...')


def free_flock():
	if LOCK_FD is not None:
		fcntl.flock(LOCK_FD, fcntl.LOCK_UN)
		LOCK_FD.close()
		os.unlink(os.path.join(BASE_PATH, 'lock'))


def encrypt_file(file: FILE, iv: bytes, key: bytes) -> (int, bytes):
	cipher = Cipher(AES256(key), CBC(iv))
	compressor = NAME_TO_COMPRESSOR[file.compression](False)
	digest = hashes.Hash(hashes.SHA512())
	encryptor = cipher.encryptor()
	encrypted = 0
	with open(file.local_path, 'rb') as f, open(file.remote_path, 'wb') as o:
		os.chmod(file.remote_path, 0o600)
		# Read file in chunks
		while True:
			chunk = f.read(4096)
			if not chunk:
				break
			digest.update(chunk)
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
	os.chmod(file.remote_path, 0o600)
	return encrypted, digest.finalize()


def decrypt_file(file: FILE, iv: bytes, key: bytes) -> None:
	cipher = Cipher(AES256(key), CBC(iv))
	decompressor = NAME_TO_COMPRESSOR[file.compression](True)
	decryptor = cipher.decryptor()
	digest = hashes.Hash(hashes.SHA512())
	decrypted = 0
	with open(file.remote_path, 'rb') as f, open(file.local_path, 'wb') as o:
		# Read file in chunks
		while True:
			chunk = f.read(4096)
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
		vprint(f'Decrypted {file.remote_path} to {file.local_path}\n\tHash: {f_hash.hex()}')
	if file.permissions != 0:
		os.chmod(file.local_path, file.permissions)


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
	counter = 0
	ret = 1
	while counter < MAX_RETRIES:
		ret = os.system(f'{UMOUNT_CMD} {MOUNT_PATH}')
		if ret != 0:
			counter += 1
			time.sleep(5)
			continue
	if ret != 0:
		exit('Failed to unmount remote storage')
	print('Unmounted.')


def exit_post_mount(status: int | str):
	unmount_remote_storage()
	free_flock()
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
	f = FILE(get_real_path(info[0]), get_real_path(info[1]), False, False, 0, 0, iv, b'', 0, 0, COMPRESSION_STR, 0,
	         False)
	f.compressed_size, _ = encrypt_file(f, iv, key)
	iv_and_size = iv + f.compressed_size.to_bytes(8, 'big')
	print(f'Generated IV-Len: {base64.b64encode(iv_and_size).decode("utf-8")}\nYou need this to decrypt the file.')
	print(f'Encrypted {info[0]} as {info[1]}')


def decrypt_file_op(info: List[AnyStr]):
	key = get_key()
	iv_and_size = base64.b64decode(info[2])
	iv = iv_and_size[:16]
	size = int.from_bytes(iv_and_size[-8:], 'big')
	f = FILE(get_real_path(info[1]), get_real_path(info[0]), False, False, 0, 0, iv, b'', 0, 0, COMPRESSION_STR, size,
	         False)
	decrypt_file(f, iv, key)
	print(f'Decrypted {info[0]} from {info[1]}')


def finish_transaction():
	print('Encrypting and backing up METADATA file...')
	SQLITE_CONNECTION.commit()
	SQLITE_CONNECTION.close()
	os.chmod(METADATA_PATH, 0o600)
	# Encrypt the metadata database
	key = get_key()
	iv = os.urandom(16)
	dest = os.path.join(MOUNT_PATH, 'METADATA-BACKUP.sqlite3.enc')
	file = FILE(METADATA_PATH, dest, False, False, 0, 0, iv, b'', 0, 0, COMPRESSION_STR, 0, False)
	file.compressed_size, sha = encrypt_file(file, iv, key)
	with open(METADATA_IV_PATH, 'w', encoding='utf-8') as f:
		f.write(f'IV:{base64.b64encode(iv).decode('utf-8')}\n')
		f.write(f'COMPRESSION:{COMPRESSION_STR}\n')
		f.write(f'SIZE:{file.compressed_size}\n')
		f.write(f'IV-Len:{base64.b64encode(iv + file.compressed_size.to_bytes(8, 'big')).decode("utf-8")}\n')
		f.write(f'SHA:{sha.hex()}\n')
	os.chmod(METADATA_IV_PATH, 0o600)
	exit_post_mount(0)


def purge_system():
	print('Purging deleted files...')
	# First we delete old files from half finished uploads
	result = SQLITE_CONNECTION.execute(GET_ALL_COLUMN, ('uploading', True)).fetchall()
	for file in result:
		file = FILE(*file)
		wprint(f'File {file.local_path} was uploading. Deleting...')
		os.remove(file.remote_path)
		SQLITE_CONNECTION.execute(DELETE_FROM_REMOTE, (file.remote_path,))
	# Now we look at the files in the db and mark them as deleted if they don't exist
	cursor = SQLITE_CONNECTION.execute(GET_ALL_NAMES_COLUMN, ('deleted', 0))
	files = [f[0] for f in cursor.fetchall()]
	for file in files:
		if os.path.exists(file):
			continue
		cursor = SQLITE_CONNECTION.execute(GET_SINGLE_FILE, (file,))
		f = cursor.fetchone()
		if f is None:
			continue
		f = FILE(*f)
		f.deleted = True
		f.deleted_at = int(datetime.datetime.now().timestamp())
		SQLITE_CONNECTION.execute(INSERT_REPLACE, f.to_sql())
		vprint(f'Marked {file} as deleted')
	# Now we look at the files in the db and delete them if they are old
	cursor = SQLITE_CONNECTION.execute(GET_ALL_COLUMN, ('deleted', 1))
	files = [FILE(*f) for f in cursor.fetchall()]
	for file in files:
		if file.deleted_at == 0:
			wprint(f'File {file.local_path} has no deleted_at timestamp, not deleting')
			continue

		if file.deleted_at + DELETE_TIMER_SECS < int(datetime.datetime.now().timestamp()):
			if os.path.exists(file.remote_path):
				os.remove(file.remote_path)
			SQLITE_CONNECTION.execute(DELETE, (file.local_path,))
			vprint(f'Deleted {file.local_path} -> {file.remote_path}')
		else:
			vprint(f'File {file.local_path} not yet ready to be purged')
	print('Purged deleted files')
	finish_transaction()


def bar_thread(t):
	with tqdm.tqdm(total=t, unit='files') as bar:
		counter = 0
		while counter < t:
			queue.get()
			counter += 1
			with mutex:
				bar.update(1)


def backup_if_sha512(file: FILE, sha: bytes, key) -> None:
	try:
		h = sha512_file(file.local_path)
		if h != sha:
			unconditional_backup(file, key)
			return
		vprint(f'File {file.local_path} the same as the last backup')
		queue.put(1)
	except Exception as e:
		wprint(f'Error hashing {file.local_path}. {e}')
		queue.put(1)


def allocate_path(file: FILE) -> AnyStr:
	while True:
		digest = hashes.Hash(hashes.SHA512())
		digest.update(os.urandom(32))
		digest.update(file.local_path.encode('utf-8'))
		unique = os.path.abspath(os.path.join(MOUNT_PATH, f'enc_{digest.finalize().hex()}'))
		with db_mutex:
			result = SQLITE_CONNECTION.execute(GET_SINGLE_FILE_REMOTE, (unique,)).fetchone()
			if result is None:
				c = copy(file)
				c.remote_path = unique
				c.local_path = unique
				SQLITE_CONNECTION.execute(INSERT, c.to_sql())
				SQLITE_CONNECTION.commit()
				return unique


def unconditional_backup(file: FILE, key) -> None:
	file.iv = os.urandom(16)
	file.remote_path = allocate_path(file)
	compressed_size, sha = (0, b'')
	while True:
		try:
			if not os.path.exists(file.local_path):
				wprint(f'File {file.local_path} does not exist')
				queue.put(1)
				return
			compressed_size, sha = encrypt_file(file, file.iv, key)
			break
		except OSError as e:
			if e.errno == 107:
				vprint(f'Remote has disconnected. Retrying...')
		except Exception as e:
			wprint(f'Error encrypting {file.local_path}. {e}')
		time.sleep(5)
	file.compressed_size = compressed_size
	file.sha512 = sha
	file.uploaded_at = int(datetime.datetime.now().timestamp())
	handle_file(file)
	queue.put(1)


def backup_dir(file: FILE) -> None:
	try:
		file.permissions = os.stat(file.local_path).st_mode
		file.uploaded_at = int(datetime.datetime.now().timestamp())
		handle_file(file)
		queue.put(1)
	except Exception as e:
		wprint(f'Error backing up {file.local_path}. {e}')
		queue.put(1)


def handle_file(result: FILE) -> None:
	if result.folder:
		with db_mutex:
			f = SQLITE_CONNECTION.execute(GET_SINGLE_FILE, (result.local_path,)).fetchone()
			if f is None:
				SQLITE_CONNECTION.execute(INSERT, result.to_sql())
				return None
		f = FILE(*f)
		if not f.folder:
			handle_old(f)
			with db_mutex:
				SQLITE_CONNECTION.execute(INSERT, result.to_sql())
				return None
		with db_mutex:
			SQLITE_CONNECTION.execute(DELETE, (result.local_path,))
			SQLITE_CONNECTION.execute(INSERT, result.to_sql())
		return None
	with db_mutex:
		f = SQLITE_CONNECTION.execute(GET_SINGLE_FILE, (result.local_path,)).fetchone()
	if f is None:
		handle_new(result)
		return None
	f = FILE(*f)
	if f.folder:
		with db_mutex:
			SQLITE_CONNECTION.execute(DELETE, (result.local_path,))
		handle_new(result)
		return None
	handle_old(f)
	handle_new(result)


def handle_old(f: FILE) -> None:
	old_path = f.local_path
	f.local_path += f'.old{datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")}'
	f.deleted = True
	f.deleted_at = int(datetime.datetime.now().timestamp())
	with db_mutex:
		SQLITE_CONNECTION.execute(DELETE, (old_path,))
		SQLITE_CONNECTION.execute(INSERT, f.to_sql())
		SQLITE_CONNECTION.commit()


def handle_new(f: FILE) -> None:
	f.uploaded_at = int(datetime.datetime.now().timestamp())
	f.uploading = False
	with db_mutex:
		# Delete temp entry used to reserve remote name
		if not f.folder:
			SQLITE_CONNECTION.execute(DELETE_FROM_REMOTE, (f.remote_path,))
		SQLITE_CONNECTION.execute(INSERT_REPLACE, f.to_sql())
		SQLITE_CONNECTION.commit()
	vprint(f'Uploaded {f.local_path} to {f.remote_path}')


def backup_system():
	def traverse_dir(p: AnyStr) -> None:
		p = os.path.abspath(p)
		if p in PATHS_TO_EXCLUDE:
			return
		if p in files_to_backup:
			vprint(f'File {p} already in backup list')
			return
		if not os.path.exists(p):
			wprint(f'Path {p} does not exist')
			return
		try:
			permissions = os.stat(p).st_mode
			if os.path.isfile(p):
				# Get file info
				size = os.path.getsize(p)
				files_to_backup[p] = FILE(p, '', False, False, 0, 0, b'', b'', size, permissions, COMPRESSION_STR, 0,
				                          True)
				return
			if os.path.isdir(p):
				items_in_dir = os.listdir(p)
				files_to_backup[p] = FILE(p, '', True, False, 0, 0, b'', b'', 0, permissions, COMPRESSION_STR, 0, False)
				for item in items_in_dir:
					traverse_dir(os.path.join(p, item))
		except PermissionError as e:
			wprint(f'Permission denied for {p}. {e}')
		except Exception as e:
			wprint(f'Error traversing {p}. {e}')

	print('Backing up system...')
	files_to_backup = {}
	for path in PATHS_TO_BACKUP:
		traverse_dir(path)
	mount_remote_storage()
	key = get_key()
	total = len(files_to_backup)
	with multiprocessing.Pool(THREADS + 1) as pool:
		pool.apply_async(bar_thread, (total,))
		# Dispatcher thread
		for file in files_to_backup.values():
			if file.folder:
				pool.apply_async(backup_dir, (file,))
				continue
			with db_mutex:
				resul = SQLITE_CONNECTION.execute(GET_SINGLE_FILE, (file.local_path,)).fetchone()
			if resul is None:
				pool.apply_async(unconditional_backup, (file, key))
				continue
			db_file = FILE(*resul)
			if file.size != db_file.size:
				pool.apply_async(unconditional_backup, (file, key))
				continue
			if args.sha:
				pool.apply_async(backup_if_sha512, (file, db_file.sha512, key))
				continue
			mod_date = os.path.getmtime(file.local_path)
			if mod_date > db_file.uploaded_at:
				pool.apply_async(unconditional_backup, (file, key))
				continue
			vprint(f'File {file.local_path} the same as the last backup')
			queue.put(1)
	purge_system()


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
		queue.put(1)
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
		pool.starmap_async(restore_file, iterable=mp_args)
		counter = 0
		while counter < total:
			queue.get()
			counter += 1
			with mutex:
				bar.update(1)
	exit_post_mount(0)


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
	METADATA_IV_PATH = os.path.join(MOUNT_PATH, 'meta_data_iv')
	PATHS_TO_BACKUP = args.paths_to_backup
	PATHS_TO_EXCLUDE = args.paths_to_exclude

	if '\\MOUNT_PATH' in PATHS_TO_BACKUP:
		wprint('Cannot backup the mount path. Removing from backup list')
		PATHS_TO_BACKUP.remove('\\MOUNT_PATH')
	if '\\MOUNT_PATH' not in PATHS_TO_EXCLUDE:
		PATHS_TO_EXCLUDE.append('\\MOUNT_PATH')

	BASE_PATH = get_real_path(BASE_PATH)
	KEY_PATH = get_real_path(KEY_PATH)
	MOUNT_PATH = get_real_path(MOUNT_PATH)
	METADATA_PATH = get_real_path(METADATA_PATH)
	METADATA_IV_PATH = get_real_path(METADATA_IV_PATH)

	# Replace special paths
	for i, path in enumerate(PATHS_TO_BACKUP):
		PATHS_TO_BACKUP[i] = get_real_path(path)

	# Expand paths
	for i, path in enumerate(PATHS_TO_EXCLUDE):
		PATHS_TO_EXCLUDE[i] = get_real_path(path)


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
		os.makedirs(MOUNT_PATH, exist_ok=True, mode=0o700)
		SQLITE_CONNECTION = sqlite3.connect(METADATA_PATH, check_same_thread=False)
		SQLITE_CONNECTION.execute(CREATE_MAIN_TABLE)
		SQLITE_CONNECTION.execute(CREATE_VARS_TABLE)
		SQLITE_CONNECTION.execute(SET_VAR, (SEPERATOR, os.sep,))
		SEPERATOR = SQLITE_CONNECTION.execute(GET_VAR, ('SEPERATOR',)).fetchone()[0]
		update_db_v0_v1()
		get_flock()
	if args.generate_key:
		generate_key()
	if args.backup:
		backup_system()
	if args.restore:
		restore_system(args.restore)
	if args.purge:
		mount_remote_storage()
		purge_system()
	if args.encrypt:
		encrypt_file_op(args.encrypt)
	if args.decrypt:
		decrypt_file_op(args.decrypt)
else:
	exit('This module is not importable')
