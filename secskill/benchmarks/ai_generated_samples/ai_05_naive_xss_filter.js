function stripScriptTags(html) {
    return html.replace(/<script>/gi, '');
}
