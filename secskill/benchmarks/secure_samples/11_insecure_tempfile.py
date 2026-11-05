import tempfile
def write_temp(content):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(content)
