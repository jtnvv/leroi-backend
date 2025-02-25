import os
import google.generativeai as genai

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-pro")

def ask_gemini(prompt: str):
    response = model.generate_content(prompt)
    return (response.text, response.usage_metadata.prompt_token_count)

def count_tokens_gemini(prompt: str):
    response = model.count_tokens(prompt)
    return (int(response.total_tokens))