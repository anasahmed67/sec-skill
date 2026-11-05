from ldap3.utils.conv import escape_filter_chars
def search_ldap(conn, user):
    safe_user = escape_filter_chars(user)
    query = f"(&(uid={safe_user})(objectClass=person))"
    return conn.search_s('dc=example,dc=com', 2, query)
