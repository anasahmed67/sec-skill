import zipfile, os
def extract_archive(zip_path, target_dir):
    with zipfile.ZipFile(zip_path, 'r') as z:
        for member in z.namelist():
            dest = os.path.realpath(os.path.join(target_dir, member))
            if not dest.startswith(os.path.realpath(target_dir)):
                raise Exception('Zip Slip detected')
        z.extractall(target_dir)
