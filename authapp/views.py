from authapp.models import Employee
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from authapp.serializer import EmployeeSerializer, UserSerializer
from django.conf import settings

from authy.api import AuthyApiClient
import phonenumbers
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_204_NO_CONTENT,
    HTTP_206_PARTIAL_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from rest_framework.viewsets import ReadOnlyModelViewSet, ModelViewSet, GenericViewSet
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from authapp.models import CustomUser
from authapp.serializer import CustomUserSerializer
from authapp.serializer import (
    PhoneTokenSerializer,
    UserTokenSerializer,
    PhoneSerializer,
)


authy_api = AuthyApiClient(settings.ACCOUNT_SECURITY_API_KEY)


class EmployeeViewSet(GenericViewSet, generics.ListCreateAPIView, generics.RetrieveUpdateDestroyAPIView):

    lookup_field = 'id'
    permission_classes = [IsAuthenticated]
    queryset = Employee.objects.all()
    serializer_class = EmployeeSerializer


class UserDetail(generics.RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

class CustomUserViewSet(ReadOnlyModelViewSet):
    """
    A simple ViewSet for viewing users.
    """

    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    url: api/token/
    2FA JWT Authentication: Step 0
    Server will generate access and refresh tokens and it will be saved in Client local storage or session storage
    POST --data-raw '{
    "username": "twilio",
    "password": "twiliopass"
}'
    """

    serializer_class = TokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        ret = super().post(request, *args, **kwargs)
        user = CustomUser.objects.get(username=request.data["username"])
        # check if user has set to true any 2FA method
        # and needs to be re-direct to 2FA verification uri
        if user.is_twofa_on(): # if user is 2FA registered (authy phone number and authy id is present)
            # request 2FA token via sms for user - send 7 digit token to user via sms
            sms = authy_api.users.request_sms(user.authy_id, {"force": True})
    
            if sms.ok():
                return Response(
                    {
                        "message": "SMS request successful. 2FA token verification expected."
                    },
                    status=HTTP_206_PARTIAL_CONTENT,
                )
            else:
                return Response(
                    {"error": sms.errors()["message"]},
                    status=HTTP_503_SERVICE_UNAVAILABLE,
                )
        
        return ret # user is not 2FA registered


class PhoneVerificationView(GenericAPIView):
    """
    url: api/2fa/phone-verify/
    --header 'Authorization: Bearer <access token>
    --data-raw '{
        "authy_phone": "+48123456789"
    }'

    2FA JWT Authentication: Step 1
    Twilio phone verification view.
    This endpoint will check if user mobile phone number is valid.
    If YES Twilio API send 4 digit verification token via SMS.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = PhoneSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        # PhoneSerializer class object has validate method (authy_api.phones.verification_start)
        # which will send sms to the registered mobile number
        if serializer.is_valid(raise_exception=True):
            return Response(status=HTTP_204_NO_CONTENT)


class PhoneRegistrationView(GenericAPIView):
    """
    url: api/2fa/phone-register/
    --header 'Authorization: Bearer <access token>
    --data-raw '{
        "authy_phone": "+48123456789",
	    "token": "1234"
    }'
    2FA JWT Authentication: Step 2
    Twilio 2FA phone registration view.
    First it will validate if 4 digit tokend sent to user phone number is valid.
    If Twilio verification check pass in next step Twilio API call will register user for 2FA
    If success: user instance will be updated with verified phone number and received from Twilio API authy_id
    """

    serializer_class = PhoneTokenSerializer
    queryset = CustomUser.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        data = request.data
        print('data in PhoneRegistrationView', data) # {'authy_phone': '+919673399646', 'token': '0842'}
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        phone = phonenumbers.parse(str(serializer.validated_data["authy_phone"]), None)
        print('phone in PhoneRegistrationView', phone)
        # create rest api client object, it creates authy_id (authy object id) - register user with 2FA
        # authy object includes user mobile number and user email if provided
        authy_user = authy_api.users.create(
            user.email, str(phone.national_number), phone.country_code, True
        )
        print('authy user in PhoneRegistrationView', authy_user)
        if authy_user.ok():
            user.authy_id = authy_user.id
            print('serializer.validated_data in PhoneRegistrationView', serializer.validated_data)
            user.authy_phone = serializer.validated_data["authy_phone"]
            user.save()
            return Response(status=HTTP_204_NO_CONTENT)
        else:
            return Response(authy_user.errors(), status=HTTP_400_BAD_REQUEST)


class AuthyTokenVerifyView(TokenObtainPairView):

    """
    url: api/2fa/token-verify/
    --data-raw '{
        "username": "twilio",
        "password": "twiliopass",
        "token": "7654321"
    }'
    2FA JWT Authentication: Step 3
    Twilio 2FA user authentication view.
    This view verify if Twilio 2FA registered user entered correct 8 digit token.
    Token will be requested by TwoFaTokenObtainPairView only for 2FA registered users
    Is success: user receive refresh and access JWT.
    """

    serializer_class = UserTokenSerializer

    def post(self, request, *args, **kwargs):
        ret = super().post(request, *args, **kwargs)
        user = CustomUser.objects.get(username=request.data["username"])
        # check if user has 2FA id assigned or if user is 2FA registered
        if user.is_twofa_on():
            # verify received 2FA token with Twilio API
            # authy rest api client user object has authy id and token
            # so the verification is done with user authy id and token present in authy user object and token sent by
            # the user
            verification = authy_api.tokens.verify(
                user.authy_id, token=request.data["token"]
            )
            print('verification in AuthyTokenVerifyView', verification)
            if verification.ok():
                # pass user instance to receive JWT
                return ret
            else:
                # return 2FA token verification error
                return Response(
                    {"error": verification.response.json()["errors"]["message"]},
                    status=HTTP_400_BAD_REQUEST,
                )
        else:
            # user has no 2FA authentication methods enabled
            return Response(
                {"error": "User not allowed for 2FA authentication."},
                status=HTTP_400_BAD_REQUEST,
            )