from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('signup', views.signup, name='accounts.signup'),
    path('login/', views.login, name='accounts.login'),
    path('logout/', views.logout, name='accounts.logout'),

    path('orders/', views.orders, name='accounts.orders'),

    path('password_reset/', views.password_reset_request, name='accounts.password_reset'),
    path('show_reset_link/', views.show_reset_link, name='accounts.show_reset_link'),
    path('reset/<uidb64>/<token>/', views.password_reset_confirm, name='accounts.password_reset_confirm'),

]