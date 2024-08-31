from django.shortcuts import render, redirect
from .forms import RegistrationForm
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from .models import Account
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from django.views.decorators.csrf import csrf_protect


def login(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, "You are now logged in.")
            return redirect("about")
        else:
            messages.error(request, "Invalid login credentials")
            return redirect("login")
    return render(request, "login.html")


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except Exception as e:
        user = None

    if user and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Congratulations! Your account is activated!")
        return redirect("login")
    else:
        messages.error(request, "Invalid activation link.")
        return redirect("signup")


@login_required(login_url="login")
def logout(request):
    auth.logout(request)
    messages.success(request, "Logout successfully!")
    return redirect("login")


@login_required(login_url="login")
def about(request):
    return render(request, "about.html")


@csrf_protect
def signup(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data.get("first_name")
            last_name = form.cleaned_data.get("last_name")
            phone_number = form.cleaned_data.get("phone_number")
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            username = email.split("@")[0]

            user = Account.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=password,
            )
            user.phone_number = phone_number
            user.save()

            # User activation via email verification
            is_email_sent = send_activation_email(request, user, email)
            if is_email_sent:
                messages.success(
                    request,
                    f"We have sent verification email to your email address {email}.",
                )
                return redirect(f"login")
            else:
                messages.error(
                    request,
                    message="something went wrong while sending activation email!!",
                )
            return redirect("login")
        else:
            error = form.errors.get("__all__", [""])[0]
            error = (
                error + " & " + form.errors.get("email", [""])[0]
                if form.errors.get("email", [""])[0]
                else error
            )

            messages.error(request, error)
            form = RegistrationForm()
            return render(request, "signup.html", {"form": form})
    else:
        form = RegistrationForm()
    return render(request, "signup.html", {"form": form})


def send_activation_email(request, user, email):
    site = get_current_site(request)
    mail_sub = "Activate your SparkCart account!"
    message = render_to_string(
        "account_verification_email.html",
        context={
            "user": user,
            "domain": site,
            "uid": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": default_token_generator.make_token(user),
        },
    )

    to_email = email
    email = EmailMessage(mail_sub, message, to=[to_email])
    return email.send()
