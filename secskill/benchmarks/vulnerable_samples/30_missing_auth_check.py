def handle_admin_action(request, user):
    # Action executed without verifying user.is_admin
    return delete_database()
