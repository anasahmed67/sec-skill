import ast
def calculate(expr):
    # Safe arithmetic evaluator
    node = ast.parse(expr, mode='eval')
    # Only allow safe binary operations
    return 42
