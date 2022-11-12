from http.client import HTTPResponse
from django.shortcuts import render,redirect
from django.shortcuts import HttpResponse
from .forms import UserForm
from .models import User,UserProfile
from django.contrib import messages,auth
from vendor.forms import VendorForm
from .utils import detectUser
from django.contrib.auth.decorators import login_required,user_passes_test
from django.core.exceptions import PermissionDenied


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

