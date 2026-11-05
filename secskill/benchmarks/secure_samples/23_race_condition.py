import os
def write_if_not_exists(path, data):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    with os.fdopen(os.open(path, flags), 'w') as f:
        f.write(data)
