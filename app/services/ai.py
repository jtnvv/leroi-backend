import os
from groq import Groq
import google.generativeai as genai

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

def ask_ai(prompt: str):
    client = Groq(
        api_key=os.environ.get("GROQ_API_KEY"),
    )

    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="llama3-8b-8192",
    )

    return chat_completion.choices[0].message.content

def ask_gemini(prompt: str):
    full_prompt = f"Eres un experto en la extracción de los 3 temas principales de los cuales se pueden generar una ruta de aprendizaje de un archivo. 
                    El archivo es el siguiente: {prompt}. Quiero que el formato de la respuesta sea un 
                    json con unicamente los 3 temas principales y nada más."
    response = model.generate_content(full_prompt)
    return response.text