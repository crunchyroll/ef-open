from collections import OrderedDict
import json
import os
import shutil
import sys

from ef_utils import assert_root
import ef_encryption


class EfLock(ef_encryption.ConfigEncryption):

    def restore_locked_copy(self, dest_filepath):
        sourcefile = ef_encryption.hash_string(dest_filepath)
        sourcefile_path = os.path.join(self.lockfile_dir, sourcefile)
        shutil.copy2(sourcefile_path, dest_filepath)

    def get_locked_copy_data(self, filepath):
        sourcefile = ef_encryption.hash_string(filepath)
        sourcefile_path = os.path.join(self.lockfile_dir, sourcefile)
        with open(sourcefile_path) as json_file:
            data = json.load(json_file, object_pairs_hook=OrderedDict)
        return data

    def get_locked_copy_data_decrypted(self, filepath):
        sourcefile = ef_encryption.hash_string(filepath)
        sourcefile_path = os.path.join(self.lockfile_dir, sourcefile)
        file_data = self.decrypt_file(sourcefile_path, write_output=False)
        return file_data

    def file_changed(self, filepath, cursor):
        current_md5 = self.get_md5sum(filepath)
        query = cursor.execute('SELECT MD5 FROM checksums WHERE FilePath=?', (filepath,))
        stored_md5 = query.fetchone()[0]
        if current_md5 == stored_md5:
            return False
        else:
            return True


def main():

    kms_clients = ef_encryption.create_kms_clients()
    repo = EfLock(kms_clients)
    assert_root()  # TODO: Not exiting properly when not in repo

    if not repo.unlocked:
        print("ef-lock currently only supports locking unlocked repos. run ef-unlock first.")
        sys.exit(1)
    else:
        db = ef_encryption.ObjectDb(repo.db_file)

        for f in repo.param_files:
            # TODO: If original file doesn't exist, lock it
            if repo.file_changed(f, db.cursor):
                with open(f, 'r') as current:
                    current_data = json.load(current, object_pairs_hook=OrderedDict)
                    original_locked = repo.get_locked_copy_data(f)
                    original_decrypted = repo.get_locked_copy_data_decrypted(f)

                    for env, params in current_data['params'].items():
                        for key, value in params.items():
                            # If this is an encrypted key use the original encryption string if the value hasn't
                            # changed (so there are no git diffs). Otherwise, encrypt the new value.
                            if key.startswith(repo.encrypted_key_prefix):
                                if key in original_locked['params'][env]:
                                    original_value = original_decrypted['params'][env][key]
                                    if value == original_value:
                                        current_data['params'][env][key] = original_locked['params'][env][key]
                                    else:
                                        current_data['params'][env][key] = repo.encrypt_secret(
                                            env=env,
                                            service=repo.get_service_from_filepath(f),
                                            secret=value)
                                else:
                                    current_data['params'][env][key] = repo.encrypt_secret(
                                        env=env,
                                        service=repo.get_service_from_filepath(f),
                                        secret=value)
                #  TODO: Detect source file format and match output (yaml vs json)
                with open(f, 'w') as current:
                    json.dump(current_data, current, indent=2, separators=(',', ': '))
                    current.write("\n")
            else:
                repo.restore_locked_copy(f)
                print("restoring {}".format(f))

        db.conn.close()
        shutil.rmtree('.ef-lock')


if __name__ == "__main__":
    # TODO: Allow for default encrypted values
    main()
