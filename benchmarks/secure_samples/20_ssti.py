from jinja2 import Environment
def render_template(user_string):
    env = Environment()
    tmpl = env.from_string("Hello {{ name }}")
    return tmpl.render(name=user_string)
