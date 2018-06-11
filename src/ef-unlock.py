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


def assert_locked():
    if ef_encryption.is_repo_unlocked():
        print("ef-unlock has already been executed on this repo. lock with ef-lock before trying again.")
        sys.exit(1)


def main():
    # TODO: Colorize these

    assert_root()
    assert_locked()

    initialize_workspace()
    settings = ef_encryption.LockConfig()

    # Create checksums db
    db = ef_encryption.ObjectDb(settings.db_file)
    create_objects_db(db.cursor)

    # Create kms clients for each account
    kms_clients = ef_encryption.create_kms_clients()

    # Create collection of all param files
    files = ef_encryption.find_param_files(settings.configdir, settings.parameter_exten)

    # Add configs dir to git ignore
    # TODO: Build this. Possibly with git skip-worktree or assume-unchanged
    git_ignore_configs()

    for f in files:

        # Create locked copy, ef-lock will restore this file later if the content of the params file is unchanged
        create_locked_copy(f['filepath'], settings.lockfile_dir)

        # Decrypt
        ef_encryption.decrypt_file(f['filepath'], kms_clients)

        # Get decrypted copy checksum. This will be used by ef-lock
        checksum = ef_encryption.get_md5sum(f['filepath'])

        # Save checksums to objects db
        db.cursor.execute("INSERT INTO checksums VALUES (?, ?)", (f['filepath'], checksum))
        db.conn.commit()

    db.conn.close()


if __name__ == "__main__":
    # TODO: Benchmark comparing md5sums with filecmp
    main()
