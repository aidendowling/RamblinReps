import re

from django.contrib.auth import login as auth_login, authenticate, update_session_auth_hash
from .forms import CustomUserCreationForm, CustomErrorList
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib import messages



def password_reset_request(request):
    if request.method == "POST":
        username = request.POST.get("username")
        try:
            user = User.objects.get(username=username)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = request.build_absolute_uri(f"/accounts/reset/{uid}/{token}/")

            # Store reset link in session
            request.session['reset_link'] = reset_link

            return redirect('accounts.show_reset_link')
        except User.DoesNotExist:
            messages.error(request, "Username not found.")  # Provide feedback to the user

    return render(request, "password_reset_form.html")

def show_reset_link(request):
    reset_link = request.session.get('reset_link', None)
    return render(request, "show_reset_link.html", {"reset_link": reset_link})

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            if request.method == "POST":
                new_password = request.POST.get("password")

                # Password validation: At least 10 characters, must include letters and numbers
                if len(new_password) < 10 or not re.search(r"[A-Za-z]", new_password) or not re.search(r"\d", new_password):
                    messages.error(request, "Password must be at least 10 characters long and include both letters and numbers.")
                    return render(request, "password_reset_confirm.html", {"valid_link": True})

                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)  # Keep user logged in
                messages.success(request, "Password has been reset successfully.")
                return redirect("accounts.login")

            return render(request, "password_reset_confirm.html", {"valid_link": True})
        else:
            messages.error(request, "Invalid or expired link.")
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, "Invalid reset link.")

    return render(request, "password_reset_confirm.html", {"valid_link": False})
@login_required
def logout(request):
    auth_logout(request)
    return redirect('home.index')

def login(request):
    template_data = {}
    template_data['title'] = 'Login'
    if request.method == 'GET':
        return render(request, 'accounts/login.html',
            {'template_data': template_data})
    elif request.method == 'POST':
        user = authenticate(
            request,
            username = request.POST['username'],
            password = request.POST['password']
        )
        if user is None:
            template_data['error'] = 'The username or password is incorrect.'
            return render(request, 'accounts/login.html',
                {'template_data': template_data})
        else:
            auth_login(request, user)
            return redirect('home.index')

def signup(request):
    template_data = {}
    template_data['title'] = 'Sign Up'
    if request.method == 'GET':
        template_data['form'] = CustomUserCreationForm()
        return render(request, 'accounts/signup.html',
            {'template_data': template_data})
    elif request.method == 'POST':
        form = CustomUserCreationForm(request.POST, error_class=CustomErrorList)
        if form.is_valid():
            form.save()
            return redirect('accounts.login')
        else:
            template_data['form'] = form
            return render(request, 'accounts/signup.html',
                {'template_data': template_data})

@login_required
def orders(request):
    template_data = {}
    template_data['title'] = 'Orders'
    template_data['orders'] = request.user.order_set.all()
    return render(request, 'accounts/orders.html',
        {'template_data': template_data})