import json
def load_data(raw_bytes):
    return json.loads(raw_bytes.decode('utf-8'))
