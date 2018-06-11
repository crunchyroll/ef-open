import os
import shutil

from ef_utils import assert_root
import ef_encryption


def is_changed(filepath, cursor):
    current_md5 = ef_encryption.get_md5sum(filepath)
    query = cursor.execute('SELECT MD5 FROM checksums WHERE FilePath=?', (filepath,))
    stored_md5 = query.fetchone()[0]
    if current_md5 == stored_md5:
        return False
    else:
        return True


def restore_locked_copy(lockfile_dir, dest_filepath):
    sourcefile = ef_encryption.hash_string(dest_filepath)
    sourcefile_path = os.path.join(lockfile_dir, sourcefile)
    shutil.copy2(sourcefile_path, dest_filepath)


def main():

    settings = ef_encryption.LockConfig()

    assert_root()  # TODO: Broken

    db = ef_encryption.ObjectDb(settings.db_file)

    files = ef_encryption.find_param_files(settings.configdir, settings.parameter_exten)

    repo_unlocked = settings.is_repo_unlocked()

    if repo_unlocked:
        for f in files:
            if is_changed(f, db.cursor):
                print("File Changed: {}".format(f))
            else:
                restore_locked_copy(settings.lockfile_dir, f)
                print("restoring {}".format(f))
        shutil.rmtree('.ef-lock')

    db.conn.close()

if __name__ == "__main__":
    main()
