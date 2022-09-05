from django.urls import path, include
from rest_framework import routers

from authapp.views import EmployeeViewSet

from authapp import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

from authapp.views import (
    PhoneVerificationView,
    PhoneRegistrationView,
    AuthyTokenVerifyView,
    CustomTokenObtainPairView,
)

router = routers.DefaultRouter()
router.register(r"employees", EmployeeViewSet)

urlpatterns = [
    path("api/", include((router.urls, "authapp"))),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path(
        "api/2fa/phone-verify/",
        PhoneVerificationView.as_view(),
        name="2fa_phone_verify",
    ),
    path(
        "api/2fa/phone-register/",
        PhoneRegistrationView.as_view(),
        name="2fa_register_phone",
    ),
    path(
        "api/2fa/token-verify/", AuthyTokenVerifyView.as_view(), name="2fa_token_verify"
    ),
    # JWT authentication uris for Rest Api
    path("api/token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),

]