from http.client import HTTPResponse
from django.shortcuts import render,redirect
from django.shortcuts import HttpResponse
from .forms import UserForm
from .models import User,UserProfile
from django.contrib import messages,auth
from vendor.forms import VendorForm
from .utils import detectUser,send_verification_email
from django.contrib.auth.decorators import login_required,user_passes_test
from django.core.exceptions import PermissionDenied
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator


#Custom decorators for restricting access to dashbaords vendor cannot access customer dashboard vice versa.

def is_vendor(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied

def is_customer(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied




# Create your views here.
def registerUser(request):
    if request.user.is_authenticated:
        messages.warning(request,'You Are Already Logged In! ')
        return redirect('myAccount')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # password = form.cleaned_data['password']
            # user = form.save(commit = False)
            # user.set_password(password)
            # user.role = User.CUSTOMER
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name,last_name=last_name,username=username,email=email,password=password)
            user.role = User.CUSTOMER
            user.save()

            mail_subject = 'Account Verification Link'
            email_template = 'accounts/emails/account_verification_email.html'

            send_verification_email(request,user,mail_subject,email_template)
            


            messages.success(request,'Your Account Has Been Created Successfully')
            return redirect('registerUser')
        else:
            if form.errors:
                print(form.errors)
    else:
        form = UserForm()
    
    context = {
        'form':form,
    }
    return render(request,'accounts/registerUser.html',context)

def registerVendor(request):
    if request.user.is_authenticated:
        messages.warning(request,'You Are Already Logged In! ')
        return redirect('myAccount')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        v_form = VendorForm(request.POST,request.FILES)
        if form.is_valid() and v_form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name,last_name=last_name,username=username,email=email,password=password)
            user.role = User.RESTAURANT
            user.save()
            vendor = v_form.save(commit=False)
            vendor.user = user
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()

            mail_subject = 'Account Verification Link'
            email_template = 'accounts/emails/account_verification_email.html'

            send_verification_email(request,user,mail_subject,email_template)
            
            messages.success(request,'Your Account Has Been Created Successfully. Please Wait For Admin Approval')
            return redirect('registerVendor')

        else:
            print(form.errors)
    else:
        form = UserForm()
        v_form = VendorForm()

    context = {
        'form' : form,
        'v_form': v_form,
    }

    return render(request,'accounts/registerVendor.html',context)


def login(request):
    if request.user.is_authenticated:
        messages.warning(request,'You Are Already Logged In! ')
        return redirect('myAccount')
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email,password=password)

        if user is not None:
            auth.login(request,user)
            messages.success(request,' You Are Now Logged In ')
            return redirect('myAccount')
        else:
            messages.error(request,' Invalid Login Details. Please Enter Correct Email And Password ')
            return redirect('login')



    return render(request,'accounts/login.html')

def logout(request):
    auth.logout(request)
    messages.info(request,' You Are Now Logged Out. ')
    return redirect('login')


@login_required(login_url='login')
@user_passes_test(is_customer)
def custDashboard(request):
    return render(request,'accounts/custDashboard.html')

@login_required(login_url='login')
@user_passes_test(is_vendor)
def vendorDashboard(request):
    return render(request,'accounts/vendorDashboard.html')

@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)


def activate(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(ValueError,TypeError,OverflowError,User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save()
        messages.success(request,'Account Verified Successfully')
        return redirect('myAccount')
    else:
        messages.error(request,'Invalid Verification Link')
        return redirect('myAccount')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)

            mail_subject = 'Password Reset Link'
            email_template = 'accounts/emails/reset_password_email.html'

            send_verification_email(request,user,mail_subject,email_template)
            messages.success(request,'Password Reset Link Has Been Sent To Your Mail Account')
            return redirect('login')
        else:
            messages.error(request,'Invalid Email, Please Enter Your Verified Email Address')
            return redirect('forgotPassword')
        
    return render(request,'accounts/forgotPassword.html')

def reset_password_validate(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(ValueError,TypeError,OverflowError,User.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid'] = uid
        messages.info(request,'Please Reset Your Password')
        return redirect('reset_password')
    else:
        messages.error(request,'Invalid Password Reset Link')
        return redirect('forgotPassword')

def reset_password(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            pk = request.session.get('uid')
            user = User.objects.get(pk=pk)
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request,'Password Changed Successfully. Please Login With Your New Password')
            return redirect('login')

        else:
            messages.error(request,'Passwords Do Not Match')
            return redirect('reset_password')
    return render(request,'accounts/reset_password.html')

