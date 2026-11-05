import zipfile
def extract_archive(zip_path, target_dir):
    with zipfile.ZipFile(zip_path, 'r') as z:
        z.extractall(target_dir)
