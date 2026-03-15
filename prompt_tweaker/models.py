from django.db import models
from django.contrib.auth.models import User

PROVIDERS = [
    ('anthropic', 'Anthropic'),
    ('openai', 'OpenAI'),
    ('google', 'Google'),
]

PARAMETER_TYPES = [
    ('str', 'intvalue'),
    ('float', 'floatvalue'),
    ('int', 'strvalue'),
]

class Profile(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

class Llm(models.Model):
    
    def __str__(self):
        return self.display_name
    
    display_name = models.CharField(max_length=32, null=False, blank=False, default="n/a")
    interaction_name = models.CharField(max_length=64, null=False, blank=False)
    provider = models.CharField(max_length=32, null=False, blank=False, default="anthropic", choices=PROVIDERS)
    context_windows = models.IntegerField()
    max_output_tokens = models.IntegerField()
    supports_streaming = models.BooleanField(default=False)
    supports_json_output = models.BooleanField(default=False)
    input_cost_per_million_tokens = models.IntegerField()
    output_cost_per_million_tokens = models.IntegerField()
    is_active = models.BooleanField(default=True)

class LlmParameter(models.Model):
    display_name = models.CharField(max_length=16, null=False, blank=False)
    interaction_name = models.CharField(max_length=16, null=False, blank=False)
    type = models.CharField(max_length=8, null=False, blank=False, default="str", choices=PARAMETER_TYPES)
    description = models.TextField()
    llm = models.ForeignKey(Llm, on_delete=models.PROTECT, null=False)
    is_active = models.BooleanField(default=True)

class Prompt(models.Model):
    system = models.TextField(null=True, default="", blank=False)
    content = models.TextField(null=False, default="Hello", blank=False)

class Message(models.Model):
    prompt = models.ForeignKey(Prompt, on_delete=models.PROTECT, null=False)
    response = models.TextField(null=False, default="")
    profile = models.ForeignKey(Profile, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class MessageParameterLlm(models.Model):
    llmparameter = models.ForeignKey(LlmParameter, on_delete=models.PROTECT, null=False)
    intvalue = models.IntegerField(default=None, null=True, blank=True)
    floatvalue = models.FloatField(default=None, null=True, blank=True)
    strvalue = models.CharField(max_length=256, default=None, null=True, blank=True)
    message = models.ForeignKey(Message, on_delete=models.PROTECT, null=False)

