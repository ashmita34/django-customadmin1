
from django.conf.urls import url
from monitoringapp import views
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
	url(r'^360admin/search/$',views.search, name='search'),
	url(r'^360admin/result/$',views.result, name='result'),
    url(r'^360admin/$', views.admin_home, name='admin_home'),
    url(r'^$', views.login, name='360login'),
    url(r'^logout/$', views.logout, name='360logout'),


    url(r'^360admin/users/$',views.user_view, name='usersmanagement'),
    url(r'^360admin/users/delete/(?P<pk>[\d]+)/$',views.delete, name='usersdelete'),
   

    url(r'^360admin/user/add/$', views.user_add, name='user_add'),





    url(r'^360admin/password/$', views.admin_password_change, name='admin_password'),
    url(r'^customer/password/$', views.change_password, name='change_password'),
    url(r'^360admin/admin_profile/$',views.admin_profile, name='admin_profile'),
    url(r'^360admin/password_reset/$',views.ResetPasswordRequestView.as_view(), name='password_reset'),
     url(r'^360admin/reset_password_confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/$',
                views.PasswordResetConfirmView.as_view(), name='reset_password_confirm'),

]