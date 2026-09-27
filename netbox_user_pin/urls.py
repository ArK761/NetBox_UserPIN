from django.urls import path

from . import views

app_name = 'netbox_user_pin'

urlpatterns = [
    path('', views.MyPinView.as_view(), name='my_pin'),
    path('set/', views.SetPinView.as_view(), name='set_pin'),
    path('change/', views.ChangePinView.as_view(), name='change_pin'),
    path('unlock/', views.UnlockView.as_view(), name='unlock'),
    path('lock/', views.LockView.as_view(), name='lock'),
    path('test/', views.PinTestView.as_view(), name='test'),
    path('test-rotation/', views.TestRotationView.as_view(), name='test_rotation'),
    path('2fa/setup/', views.TotpSetupView.as_view(), name='totp_setup'),
    path('2fa/<str:action>/', views.TotpManageView.as_view(), name='totp_manage'),
    path('recover/', views.RecoverView.as_view(), name='recover'),
    path('confirm/', views.StepUpView.as_view(), name='step_up'),
    path('users/', views.UserPinListView.as_view(), name='user_list'),
    path('users/<int:pk>/<str:action>/', views.UserPinActionView.as_view(), name='user_action'),
    path('events/', views.PinEventListView.as_view(), name='event_list'),
    path('settings/', views.PinSettingsView.as_view(), name='settings'),
    path('delegates/', views.DelegateListView.as_view(), name='delegates'),
]
