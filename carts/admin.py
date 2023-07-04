from django.contrib import admin
from .models import Cart, CartItems

class CartAdmin(admin.ModelAdmin):
    list_display = ("id", "date_added")

class CartItemsAdmin(admin.ModelAdmin):
    list_display = ("product", "cart", 'quantity', 'is_active')

admin.site.register(Cart, CartAdmin)
admin.site.register(CartItems, CartItemsAdmin)
