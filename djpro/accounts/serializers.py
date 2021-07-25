from django.contrib.auth.models import User, Group
from rest_framework import serializers
from django.core.validators import EmailValidator
#from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    #user_pk=serializers.Field(source=User.id)
    class Meta:
        model = User
        fields = ['id', 'username', 'email',]
        #lookup_field='user_pk'




class RegisterSerializer(serializers.ModelSerializer):
    email =serializers.EmailField()
    class Meta:
        model = User
        fields = ('id','username','email','password')
        extra_kwargs = {'password':{'write_only': True},'email':{'validators':[EmailValidator,]}
        }
    def validate_email(self,value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("email already exists.")
        return value

    def create(self,validated_data):
        user = User.objects.create_user(validated_data['username'],validated_data['email'],validated_data['password'])
        return user



class LoginSerializer(serializers.Serializer):

    
    username = serializers.CharField()
    password = serializers.CharField()
    def validate(self,data):
        user =authenticate(**data)
        if user and user.is_active:
            return user
        #else:
            #print('incorrect')
        
        raise serializers.ValidationError("incorrect Credentials")