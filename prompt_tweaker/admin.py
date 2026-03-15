from django.contrib import admin
from .models import Llm

class LlmAdmin(admin.ModelAdmin):
    pass

admin.site.register(Llm, LlmAdmin)
