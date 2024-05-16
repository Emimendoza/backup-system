```
usage: backup-system [-h] [-g] [-v] [-t THREADS] [-c COMPRESS] [--sha] [--base-path BASE_PATH] [--delete-timer-secs DELETE_TIMER_SECS] [-e <in-path> <out-path>]
                     [-d <in-path> <out-path> <IV-Len>] [-b] [-r [RESTORE ...]] [-p] [-s SSH] [--delete_timer DELETE_TIMER] [--paths_to_backup [PATHS_TO_BACKUP ...]]
                     [--paths_to_exclude [PATHS_TO_EXCLUDE ...]]

Backup system to remote storage, encrypting each file with AES256

options:
  -h, --help            show this help message and exit
  -g, --generate-key    Generate a new symmetric key
  -v, --verbose         Verbose output
  -t THREADS, --threads THREADS
                        Number of threads to use
  -c COMPRESS, --compress COMPRESS
                        Compress files before encrypting
  --sha                 Use sha512 to check if file has been modified as opposed to mtime
  --base-path BASE_PATH
                        Base path for the db and mount dir.
  --delete-timer-secs DELETE_TIMER_SECS
                        Delete timer in seconds
  -e <in-path> <out-path>, --encrypt <in-path> <out-path>
                        Encrypt file.
  -d <in-path> <out-path> <IV-Len>, --decrypt <in-path> <out-path> <IV-Len>
                        Decrypt file.
  -b, --backup          Backup system to remote storage, implies -p
  -r [RESTORE ...], --restore [RESTORE ...]
                        Restore system from remote storage (optional: restore specific paths)
  -p, --purge           Purge old deleted files from remote storage
  -s SSH, --ssh SSH     SSH connection string. Required by r/b/p. e.g. user@host:/path/to/storage
  --delete_timer DELETE_TIMER
                        Delete timer in seconds
  --paths_to_backup [PATHS_TO_BACKUP ...]
                        Paths to backup
  --paths_to_exclude [PATHS_TO_EXCLUDE ...]
                        Paths to exclude

Additional Notes: 
- Each file is individually encrypted with AES256 
- The iv of each file is stored in the metadata database 
- The database is also encrypted but the iv is placed in a separate file and in plane text 
- The options `-e` and `-d` are for manual file encryption and decryption and the IV-Len is NOT stored in the db. 
- The following special paths can be used: 
        \BASE_PATH: The base path of the backup system (default: ~/.backup_system/) 
        \KEY_PATH: The path to the symmetric key (default: ~/.backup_system/aes256_key.priv) 
        \MOUNT_PATH: The path where the remote storage is mounted (default: ~/.backup_system/mount/) 
        \METADATA_PATH: The path to the metadata database (default: ~/.backup_system/METADATA-BACKUP.sqlite3) 
        \METADATA_IV_PATH: The path to the metadata database iv (default: ~/.backup_system/mount/meta_data_iv) 
- The metadata database is used to keep track of the files and their metadata 
- By default, deleted files will take 1 week to be deleted off the remote 
- By default, files that have been modified will have the string '.old<TIMESTAMP>' appended to  
  the old filename in the db and will have the old version deleted after 1 week. 
- Passing 'none' to --ssh will result in no remote storage being used.
- IV-Len is the IV followed by the size of the file in bytes. (16 bytes IV + 8 bytes big endian size)
- The `-c` option takes one of the following: none, xz
Author: Emilio Mendoza Reyes
```
