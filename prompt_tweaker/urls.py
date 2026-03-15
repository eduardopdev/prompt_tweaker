from .views import login_page, prompt_tweaker, message_claude

from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("", login_page, name="login_page"),
    path("prompt_tweaker", prompt_tweaker, name="prompt_tweaker"),
    path("message_claude", message_claude, name="message_claude")
]
