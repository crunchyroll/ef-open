import os.path
import shutil

import sys

import ef_encryption
from ef_utils import assert_root


def create_locked_copy(file_path, destination):
    locked_copy = ef_encryption.hash_string(file_path)
    locked_copy_filepath = os.path.join(destination, locked_copy)
    shutil.copy2(file_path, locked_copy_filepath)


def create_objects_db(cursor):
    cursor.execute('''CREATE TABLE checksums
                     (FilePath text NOT NULL, MD5 text NOT NULL, PRIMARY KEY (FilePath))''')


def initialize_workspace():
    dirs = ['.ef-lock', '.ef-lock/locked']
    for d in dirs:
        try:
            os.stat(d)
        except OSError:
            os.mkdir(d)


def git_ignore_configs():
    pass


def main():

    assert_root()  # TODO: Not exiting properly
    initialize_workspace()
    kms_clients = ef_encryption.create_kms_clients()
    config_repo = ef_encryption.ConfigEncryption(kms_clients)

    if config_repo.unlocked:
        print("ef-unlock has already been executed on this repo. lock with ef-lock before trying again.")
        sys.exit(1)

    # Create checksums db
    db = ef_encryption.ObjectDb(config_repo.db_file)
    create_objects_db(db.cursor)

    # Add configs dir to git ignore
    # TODO: Build this. Possibly with git skip-worktree or assume-unchanged
    git_ignore_configs()

    for f in config_repo.param_files:

        # Create locked copy, ef-lock will restore this file later if the content of the params file is unchanged
        create_locked_copy(f, config_repo.lockfile_dir)

        # Decrypt
        config_repo.decrypt_file(f, kms_clients)

        # Get decrypted copy checksum. This will be used by ef-lock
        checksum = config_repo.get_md5sum(f)

        # Save checksums to objects db
        db.cursor.execute("INSERT INTO checksums VALUES (?, ?)", (f, checksum))
        db.conn.commit()

    db.conn.close()


if __name__ == "__main__":
    # TODO: Benchmark comparing md5sums with filecmp
    main()
