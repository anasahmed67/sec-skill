def query_database(sql):
    try:
        return run_query(sql)
    except Exception as e:
        # AI leaked full stack trace and SQL query to client
        return {'error': str(e), 'query': sql}, 500
