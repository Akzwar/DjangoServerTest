# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse

from xgameauth.models import *

import json

@csrf_exempt
def register( request ):
    body = json.loads( request.body )

    username = body["username"]
    password = body["password"]

    user = User()
    user.username = username
    user.password = password

    user.save()

    return JsonResponse( { "result" : "OK" } )

@csrf_exempt
def authorize( request ):
    body = json.loads( request.body )

    username = body["username"]
    password = body["password"]

    try:
        user = User.objects.all().get( username = username )
    except:
        return JsonResponse( { "result" : "Wrong username" } )
    if user.password != password:
        return JsonResponse( { "result" : "Wrong password" } )

    try:
        token = AuthToken.objects.all().get( user = user )
    except:
        token = AuthToken()
        token.user = user
        token.save()

    user_data = {}
    user_data["username"] = user.username

    return JsonResponse( { "result" : "OK", "token" : str( token.guid ), "user_data" : user_data } )

@csrf_exempt
def authorize_by_token( request ):
    token_guid = request.META.get('HTTP_X-AUTH-SUBJECT')
    if token_guid == None:
        token_guid = request.META.get( 'HTTP_XAUTHSUBJECT' )
    if token_guid == None:
        token_guid = request.META.get( 'HTTP_X_AUTH_SUBJECT' )
    if token_guid == None:
        return JsonResponse( { "result" : "Authorization error" } )
    if token_guid[0] == '"':
        token_guid = token_guid[1:-1]
    try:
        token = AuthToken.objects.all().get( guid = token_guid )
    except AuthToken.DoesNotExist:
        return JsonResponse( { "result" : "Authorization error" } )

    user = token.user

    user_data = {}
    user_data["username"] = user.username

    return JsonResponse( { "result" : "OK", "user_data" : user_data } )
