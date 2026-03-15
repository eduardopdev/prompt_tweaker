from django.shortcuts import render
from django.http import JsonResponse
from dotenv import load_dotenv
from anthropic import Anthropic
import os

# Load environment variables
load_dotenv()

def login_page(request):
    return render(request, 'login_page.html')

def prompt_tweaker(request):
    return render(request, 'message_page.html')

def message_claude(request):
    if request.method in ['GET', 'HEAD', 'PUT', 'DELETE']:
        return JsonResponse({"answer": 'REQ MAL FORMADA'})
    
    request_prompt = request.POST.get('prompt', '').strip()
    
    temperature = request.POST.get('temperature', '').strip()
    temperature = float(temperature)

    top_k = request.POST.get('top_k', 30)
    top_k = int(top_k)
    if top_k > 100:
        top_k = 30

    max_tokens = request.POST.get('max_tokens', 1024)
    max_tokens = int(max_tokens)
    if max_tokens < 1:
        max_tokens = 1024
    if max_tokens > 4096:
        max_tokens = 1024

    if not request_prompt:
        llm_response = 'RECEBI UM PROMPT VAZIO'
        return JsonResponse({"answer": llm_response})
    
    api_key = os.getenv('ANTHROPIC_API_KEY')
    client = Anthropic(api_key=api_key)
    
    request_kwargs = {
        "model": "claude-opus-4-6",
        "temperature": temperature,
        "top_k": top_k,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": request_prompt}],
    }
    
    print(request_kwargs)

    message = client.messages.create(**request_kwargs)
    
    llm_response = message.content[0].text
    return JsonResponse({"answer": message})