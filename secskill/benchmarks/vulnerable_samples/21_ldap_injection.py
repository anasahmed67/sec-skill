def search_ldap(conn, user):
    query = f"(&(uid={user})(objectClass=person))"
    return conn.search_s('dc=example,dc=com', 2, query)
