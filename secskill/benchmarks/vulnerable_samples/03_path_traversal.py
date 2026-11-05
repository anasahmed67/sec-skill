def read_file(base_dir, filename):
    with open(f"{base_dir}/{filename}", 'r') as f:
        return f.read()
