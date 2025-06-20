# llm_service.py

import base64
import os
# LangChain & Groq imports
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser, JsonOutputParser

from dotenv import load_dotenv


load_dotenv()

encoded_key = os.getenv("GROQ_API_KEY")
if not encoded_key:
    raise ValueError("GROQ_API_KEY manquant dans les variables d’environnement.")
GROQ_API_KEY = base64.b64decode(encoded_key).decode()

# -- Création de l'objet LLM sécurisé --
llm = ChatGroq(
    api_key=GROQ_API_KEY,
    model="mixtral-8x7b-32768"
)

# Fonctions AI centralisées
def summarize_text(text, style="bullet_points"):
    prompt = ChatPromptTemplate.from_template("""
    Résume le texte suivant en français au format {style} :

    Texte :
    {text}
    """)
    chain = prompt | llm
    return chain.invoke({"text": text, "style": style}).content.strip()


def translate_text(text, lang="en"):
    prompt = ChatPromptTemplate.from_template("""
    Traduis ce texte en {lang} :

    {text}
    """)
    chain = prompt | llm
    return chain.invoke({"text": text, "lang": lang}).content.strip()


def correct_text(text):
    prompt = ChatPromptTemplate.from_template("""
    Corrige les fautes d'orthographe et de grammaire du texte suivant sans changer son style :

    {text}
    """)
    chain = prompt | llm
    return chain.invoke({"text": text}).content.strip()


def generate_text(prompt_input, context=""):
    full_prompt = f"""
    {context}

    Consigne :
    {prompt_input}
    """
    return llm.invoke(full_prompt).content.strip()



def generate_chat_response(messages):
    return llm.invoke(messages).content.strip()


