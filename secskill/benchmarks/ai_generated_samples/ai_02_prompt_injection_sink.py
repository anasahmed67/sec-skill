def ask_agent(user_query):
    prompt = f"SYSTEM: You are a secure assistant.\nUSER: {user_query}"
    return call_llm(prompt)
