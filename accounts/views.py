from django.utils.http import urlsafe_base64_decode
from django.http import HttpResponse
from django.shortcuts import redirect, render
from accounts.models import Account
from carts.models import Cart, CartItems
from .forms import RegistrationForm
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from carts.views import _cart_id

def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data["first_name"]
            last_name = form.cleaned_data["last_name"]
            phone_number = form.cleaned_data["phone_number"]
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            username = email.split("@")[0]
            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                username=username,
                password=password
            )
            user.phone_number = phone_number
            user.save()

            current_site = get_current_site(request)
            mail_subject = "Please activate your account"
            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])  # Fixed typo here
            send_email.send()
            # messages.success(request, "Thanks for registering. Please check your email for the verification message!")

            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()  # Fixed typo here
    context = {
        "form": form,
    }
    return render(request, "accounts/register.html", context)

def login(request):
    if request.method == 'POST':
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = auth.authenticate(request, email=email, password=password)
        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists = CartItems.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_items = CartItems.objects.filter(cart=cart)
                    for item in cart_items:
                        item.user = user
                        item.save()
            except Cart.DoesNotExist:
                pass
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid login credentials")
            return redirect('login')
    return render(request, "accounts/login.html")

@login_required(login_url="login")
def logout(request):
    auth.logout(request)
    messages.success(request, "You are logged out")
    return redirect('login')

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Congratulations! Your account is activated.")
        return redirect('login')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('register')
    
@login_required(login_url="login")
def dashboard(request):
    return render(request, "accounts/dashboard.html")

def forgotPassword(request):
    if request.method == "POST":
        email = request.POST["email"]
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            current_site = get_current_site(request)
            mail_subject = 'Reset your Password'
            message = render_to_string('accounts/reset_password_email.html',{
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            messages.success(request, 'password reset email hes been sent to your email')
            return redirect('login')
        else:
            messages.error(request, 'account does not ex')
            return redirect('forgotPassword')
    return render(request, 'accounts/forgotPassword.html')

def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password.')
        return redirect('resetPassword')
    else:
        messages.error(request, 'This link is invalid.')
        return redirect('login')

def resetPassword(request):
    if request.method == 'POST':
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        if password == confirm_password:
            uid = request.session.get("uid")
            try:
                user = Account.objects.get(pk=uid)
                user.set_password(password)
                user.save()
                messages.success(request, "Password reset successful.")
                return redirect('login')
            except Account.DoesNotExist:
                messages.error(request, 'Invalid user.')
        else:
            messages.error(request, 'Passwords do not match.')
    return render(request, 'accounts/resetPassword.html')
