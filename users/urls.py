from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.user_registration_view, name='register'),
    path('verify-email/<str:uidb64>/<str:token>/', views.email_verification_view, name='verify-email'),
    path('password-reset/', views.password_reset_view, name='password-reset'),
    path('change-password/<int:user_id>/', views.change_password_view, name='change-password'),
    path('update-profile/<int:user_id>/', views.update_profile_view, name='update-profile'),
    path('close-account/<int:user_id>/', views.close_account_view, name='close-account'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
]
