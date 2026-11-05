import os
def make_cache_dir():
    os.makedirs('/tmp/my_app_cache', mode=0o700, exist_ok=True)
