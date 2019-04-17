
from django.shortcuts import render, redirect,HttpResponseRedirect,reverse
from django.contrib import auth, messages
from django.contrib.auth import authenticate

from django.template.context import RequestContext
from django.db.models import Q
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.views.generic import *
from django.db.models.query_utils import Q
from django.db.models import Count

from monitoringapp.forms import PasswordResetRequestForm,SetPasswordForm,UserForm
from vacker360_admin import settings
from django.contrib.auth.hashers import make_password

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash


# Create your views here.
class ResetPasswordRequestView(FormView):

        template_name = "monitoringapp/password_reset_confirm.html"    #code for template is given below the view's code
        success_url = '/360admin/'
        form_class = PasswordResetRequestForm

        @staticmethod
        def validate_email_address(email):
        
        #This method here validates the if the input is an email address or not. Its return type is boolean, True if the input is a email address or False if its not.
        
            try:
                validate_email(email)
                return True
            except ValidationError:
                return False

        def post(self, request, *args, **kwargs):
        
        #A normal post request which takes input from field "email_or_username" (in ResetPasswordRequestForm). 
        
            form = self.form_class(request.POST)
            if form.is_valid():
                data= form.cleaned_data["email_or_username"]
            if self.validate_email_address(data) is True:                 #uses the method written above
                '''
                If the input is an valid email address, then the following code will lookup for users associated with that email address. If found then an email will be sent to the address, else an error message will be printed on the screen.
                '''
                associated_users= User.objects.filter(Q(email=data)|Q(username=data))
                if associated_users.exists():
                    for user in associated_users:
                            c = {
                                'email': user.email,
                                'domain': request.META['HTTP_HOST'],
                                'site_name': 'Monitoring SYstem',
                                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                'user': user,
                                'token': default_token_generator.make_token(user),
                                'protocol': 'http',

                                }
                            subject_template_name='monitoringapp/password_reset_subject.txt' 
                            # copied from django/contrib/admin/templates/registration/password_reset_subject.txt to templates directory
                            email_template_name='monitoringapp/password_reset_email.html'    
                            # copied from django/contrib/admin/templates/registration/password_reset_email.html to templates directory
                            subject = loader.render_to_string(subject_template_name, c)
                            # Email subject *must not* contain newlines
                            subject = ''.join(subject.splitlines())
                            email = loader.render_to_string(email_template_name, c)
                            send_mail(subject, email, settings.SERVER_EMAIL  , [user.email], fail_silently=False)
                    result = self.form_valid(form)
                    messages.success(request, 'An email has been sent to ' + data +". Please check its inbox to continue reseting password.")
                    return result
                result = self.form_invalid(form)
                messages.error(request, 'No user is associated with this email address')
                return result
            else:
                '''
                If the input is an username, then the following code will lookup for users associated with that user. If found then an email will be sent to the user's address, else an error message will be printed on the screen.
                '''
                associated_users= User.objects.filter(username=data)
                if associated_users.exists():
                    for user in associated_users:
                        c = {
                            'email': user.email,
                            'domain': request.META['HTTP_HOST'], #or your domain
                            'site_name': '',
                            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                            'user': user,
                            'token': default_token_generator.make_token(user),
                            'protocol': 'http',
                            }
                        subject_template_name='monitoringapp/password_reset_subject.txt'
                        email_template_name='monitoringapp/password_reset_email.html'
                        subject = loader.render_to_string(subject_template_name, c)
                        # Email subject *must not* contain newlines
                        subject = ''.join(subject.splitlines())
                        email = loader.render_to_string(email_template_name, c)
                        #send_mail(subject, message, settings.SERVER_EMAIL,[request.POST['email']],fail_silently=False)
                        send_mail(subject, email, settings.SERVER_EMAIL , [user.email], fail_silently=False)
                    result = self.form_valid(form)
                    messages.success(request, 'Email has been sent to ' + data +"'s email address. Please check its inbox to continue reseting password.")
                    return result
                result = self.form_invalid(form)
                messages.error(request, 'This username does not exist in the system.')
                return result
            messages.error(request, 'Invalid Input')
            return self.form_invalid(form)

class PasswordResetConfirmView(FormView):
    template_name = "monitoringapp/password_reset_form.html"
    success_url = '/360admin/'
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password= form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                return self.form_valid(form)
            else:
                messages.error(request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(request,'The reset password link is no longer valid.')
            return self.form_invalid(form)

def admin_home(request):
    if not request.user.is_superuser and not request.user.is_authenticated():
        return redirect('360logout')
    return render(request, 'monitoringapp/admin_home.html')

def login(request):

    if request.user.is_authenticated() and request.user.is_superuser:
        #To redirect to different pages
        #=print(request.user.is_superuser)
        return redirect('admin_home')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user and user.is_authenticated():
            if user.is_superuser:
                auth.login(request, user)
                return redirect('admin_home')
           
        else:
            messages.error(request, 'Please enter correct username and password')
            return render(request, 'monitoringapp/login.html')

    return render(request, 'monitoringapp/login.html')

def logout(request):
    auth.logout(request)
    return redirect('360login')


def search(request):    
    return render(request, 'monitoringapp/search.html')


def result(request):
    results = []
    if request.is_ajax():
        q = request.GET.get('q')
        if q:
            not_superuser = Q(is_superuser=False)
            username_filter = Q(username__contains = q)           
            results = User.objects.filter(not_superuser & username_filter) 
    return render(request, 'monitoringapp/result.html', {'results': results})


@login_required
def admin_password_change(request):
    if not request.user.is_authenticated() or not request.user.is_superuser:
        return redirect('360logout')
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request,user) #Important
            messages.success(request, "Your password was successfully updated.")
            return redirect('change_password')

        else:
            messages.error(request,"Please correct the error below")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'monitoringapp/admin_password.html',{
        'form' :form        
        })


def change_password(request):
    
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request,user) #Important
            messages.success(request, "Your password was successfully updated.")
            return redirect('change_password')

        else:
            messages.error(request,"Please correct the error below")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'monitoringapp/password_change.html',{
        'form' :form        
        })

@login_required
def user_view(request):
    if not request.user.is_authenticated() or not request.user.is_superuser:
        return redirect('360logout')
    users = User.objects.all()    
    return render(request, 'monitoringapp/userview.html', {
        'users': users,
    })




@login_required
def admin_profile(request):
    if not request.user.is_authenticated() or not request.user.is_superuser:
        return redirect('360logout')  


        

    user_id = request.session.get('_auth_user_id')
    try:
        user = User.objects.get(id=user_id)
    except Exception as e:
        user = None

    if user is not None:
        if request.method == "POST":
            form = UserForm(request.POST, instance= user)
            if form.is_valid():
                form.save()
                messages.success(request, "Your Profile was successfully updated")
                return redirect(reverse('admin_profile'))
            else:
                messages.error(request, "Please correct the error below.")
        else:
            form = UserForm(instance=user)  

    return render( request, 'monitoringapp/admin_profile.html',{'form':form,
        'user':user})


@login_required
def user_add(request):
    if not request.user.is_authenticated() or not request.user.is_superuser:
        return redirect('360logout')    

    if request.method == 'POST':    
        user_form = UserForm(request.POST)
        password_raw = request.POST.get('password')
        #customer_form = CustomerForm(request.POST)
        mutable = request.POST._mutable
        request.POST._mutable = True
        request.POST['password'] = make_password(request.POST.get('password'))
        request.POST._mutable = mutable

        if user_form.is_valid():

            #user.set_password(user_form.cleaned_data['password'])
            #user.save()
            user_form.save()
            #user_id = User.objects.filter(username=request.POST.get('username'))[0].id
            #customer_form.cleaned_data['user_id'] = user_id
            #customer_form.save()
            messages.success(request, 'Your profile was successfully updated!')

            #send email to user
            #subject = "Vacker Monitoring App"
            #message = '''Welcome to Vacker Monitoring App. Your Sign in credentials are given below:
#Username :'''+request.POST['username']+'''\n Password: '''+ password_raw +'''\n Please Reset your password the first time you login.
#You can change your password here \n\n{0}://{1}/customer/password\n

#Vacker360

#Kathmandu, Nepal

#Email Disclaimers

# Part of Vacker Global Group | 306, RKM Building | Hor Al Anz | Deira
# PO Box 92438 | Dubai | UAE
# Phone : (+971) 42 66 11 44 | Fax : (+971) 42 66 11 55

# An ISO 9001:2015 & OSHAS 18001:2007 certified company

# VACKER IS GREEN... Please file this email in an email folder and save a tree"'''.format(request.scheme, request.get_host())
#             #template="customers/password_change.html"

            # try:
            #     send_mail(subject, message, settings.SERVER_EMAIL,[request.POST['email']],fail_silently=False)
            #     messages.add_message(request, messages.INFO,'Email Sent')
            # except Exception as e:
            #     print(e)
            #     messages.add_message(request, messages.INFO,'Unable to send email')

            return redirect('usersmanagement')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        user_form = UserForm()
        #customer_form = CustomerForm()
    return render(request, 'monitoringapp/user_add.html', {
    'user_form': user_form,
    #'customer_form': customer_form
    })
    
def delete(request,pk):
    object_ = User.objects.filter(pk=pk)
    object_.delete()
    return redirect('usersmanagement')
