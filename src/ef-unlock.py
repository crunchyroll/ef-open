import os.path
import shutil
import sys

import ef_encryption
from ef_utils import assert_root


def create_locked_copy(file_path, destination):
    locked_copy = ef_encryption.hash_string(file_path)
    locked_copy_filepath = os.path.join(destination, locked_copy)
    shutil.copy2(file_path, locked_copy_filepath)


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
    repo = ef_encryption.ConfigEncryption(kms_clients)

    if repo.unlocked:
        print("ef-unlock has already been executed on this repo. lock with ef-lock before trying again.")
        sys.exit(1)

    db = ef_encryption.ObjectDb(repo.db_file)
    db.create_checksums_schema()

    # Add configs dir to git ignore
    # TODO: Build this. Possibly with git skip-worktree or git assume-unchanged
    git_ignore_configs()

    for f in repo.all_param_files:

        # Create locked copy, ef-lock will restore this file later if the content of the params file is unchanged
        create_locked_copy(f, repo.lockfile_dir)

        # Decrypt
        repo.decrypt_file(f, kms_clients)

        # Get decrypted copy checksum. This will be used by ef-lock
        checksum = repo.get_md5sum(f)

        # Save checksums to objects db
        db.cursor.execute("INSERT INTO checksums VALUES (?, ?)", (f, checksum))
        db.conn.commit()

    db.conn.close()


if __name__ == "__main__":
    # TODO: Benchmark comparing md5sums with filecmp
    main()
