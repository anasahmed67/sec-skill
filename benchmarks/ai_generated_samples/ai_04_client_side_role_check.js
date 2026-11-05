function canEditPost(user, post) {
    // AI placed permission check in client script only
    return user.role === 'admin';
}
