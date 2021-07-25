from django.shortcuts import render


# Create your views here.
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from .serializers import UserSerializer,RegisterSerializer,LoginSerializer
from rest_framework import response, status

from django.contrib.auth import login

from rest_framework import permissions
from rest_framework.authtoken.serializers import AuthTokenSerializer





class ListUsers(APIView):
    serializer_class = UserSerializer
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        usernames = [user.username for user in User.objects.all()]
        return Response(usernames)




class RegisterApi(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            #instance,created = User.objects.update_or_create(email=serializer.validated_data.get('email',None),defaults=serializer.validated_data)
            #return response.Response(serializer.data,status=status.HTTP_200_OK)
            return Response({
                'user': UserSerializer(user,context=self.get_serializer_context()).data,
                'token': token.key,
                #'created': Response(serializer.data,status = status.HTTP_200_OK),
                
                
            }) 
                #response.Response(serializer.data,status=status.HTTP_200_OK)
        return response.Response(serializer.data,status=stauus.HTTP_400_BAD_REQUESTS)
                
            
        








class LoginAPI(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'user': UserSerializer(user,context=self.get_serializer_context()).data,
            'token': token.key,
            
        })





class UserAPI(generics.RetrieveAPIView):
    
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
        #authentication_classes = [authentication.TokenAuthentication]
    

    def get_object(self):
        
        return self.request.user