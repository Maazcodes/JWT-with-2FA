from django.contrib import admin
from authapp.models import Employee, CustomUser

admin.site.register(Employee)
admin.site.register(CustomUser)
