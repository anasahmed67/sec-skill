def handle_admin_action(request, user):
    if not getattr(user, 'is_admin', False):
        raise PermissionError('Unauthorized')
    return delete_database()
