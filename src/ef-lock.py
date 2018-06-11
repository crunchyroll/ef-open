import os
import os.path
import sys

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


def main():

    repo_unlocked = False
    settings = ef_encryption.LockConfig()

    assert_root()  # TODO: Broken

    db = ef_encryption.ObjectDb(settings.db_file)

    files = ef_encryption.find_param_files(settings.configdir, settings.parameter_exten)

    # try:
    #     os.stat(settings.dbfile)
    #     repo_unlocked = True
    # except OSError:
    #     pass

    repo_unlocked = ef_encryption.is_repo_unlocked()

    if repo_unlocked:
        for f in files:
            if is_changed(f['filepath'], db.cursor):
                print("File Changed: {}".format(f['filepath']))


if __name__ == "__main__":
    main()
