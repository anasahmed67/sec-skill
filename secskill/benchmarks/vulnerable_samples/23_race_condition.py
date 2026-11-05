import os
def write_if_not_exists(path, data):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(data)
