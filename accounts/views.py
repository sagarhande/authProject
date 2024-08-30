from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse
from .forms import RegistrationForm
from django.contrib.auth import get_user_model
from django.contrib import messages, auth


def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            url = request.META.get('HTTP_REFERER')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'login.html')


def logout(request):
    pass


def about(request):
    return render(request, "about.html")


def signup(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Prevent login until email is verified
            user.save()
            # Send email verification
            send_verification_email(request, user)
            return redirect("email_sent_page")
    else:
        form = RegistrationForm()
    return render(request, "signup.html", {"form": form})


def send_verification_email(request, user):
    subject = "Verify your account"
    message = "Follow this link to verify your account: {}".format(
        request.build_absolute_uri(reverse("verify_email", args=[user.id]))
    )
    send_mail(subject, message, "from@example.com", [user.email])


def verify_email(request, user_id):
    user = get_user_model().objects.get(id=user_id)
    user.is_active = True
    user.save()
    return redirect("login")
