from jinja2 import Template
def render_template(user_string):
    return Template(f"Hello {user_string}").render()
