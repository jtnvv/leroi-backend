import os
import google.generativeai as genai

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

def ask_gemini(prompt: str):
    response = model.generate_content(prompt)
    return response.text