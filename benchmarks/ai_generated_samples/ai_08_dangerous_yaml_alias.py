import yaml
def load_ai_spec(content):
    # AI used FullLoader assuming it prevents code execution
    return yaml.load(content, Loader=yaml.FullLoader)
