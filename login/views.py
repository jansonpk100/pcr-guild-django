import json

from django.http.response import HttpResponseForbidden, HttpResponseBadRequest, HttpResponseNotFound, HttpResponse
from django.contrib import auth
from django.db.utils import IntegrityError

from .models import User


class HttpUnauthorized(HttpResponse):
    status_code = 401


def login(request):
    if request.method == 'POST':
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        username = query.get('username')
        password = query.get('password')
        user = auth.authenticate(username=username, password=password)
        if not user:
            # 验证失败 400
            return HttpResponseBadRequest('Incorrect username or password.')
        auth.login(request, user)
        return HttpResponse()
    return HttpResponseNotFound()


def register(request):
    if request.method == 'POST':
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        username = query.get('username')
        password = query.get('password')
        if len(username) < 4 or len(username) > 16:
            # 用户名长度不正确 400
            return HttpResponseBadRequest('The limit of the length of a username is 4~16')
        if len(password) < 4 or len(password) > 16:
            # 密码长度不正确 400
            return HttpResponseBadRequest('The limit of the length of a password is 4~24')
        try:
            user = User.objects.create_user(username=username, password=password)
        except (IntegrityError, ValueError):
            # 用户已存在 400
            return HttpResponseBadRequest('User already exists.')
        auth.login(request, user)
        return HttpResponse()
    return HttpResponseNotFound()


def logout(request):
    if request.method in ('POST', 'GET'):
        auth.logout(request)
        return HttpResponse()
    return HttpResponseNotFound()


def set_password(request):
    """
    修改用户密码
    URL: /api/set_password/
    Method: POST
    Permission: 登录用户
    Param:
        password: 现密码
        new_password: 新密码
    """
    if request.method == 'POST':
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        password = query.get('password')
        if not request.user.check_password(password):
            # 参数错误 400
            return HttpResponseBadRequest('Incorrect password.')
        new_password = query.get('new_password')
        if len(new_password) < 4 or len(new_password) > 16:
            # 密码长度不正确 400
            return HttpResponseBadRequest('The limit of the length of a password is 4 ~ 24')
        request.user.set_password(new_password)
        request.user.save()
        return HttpResponse()
    return HttpResponseNotFound()


def remove(request):
    """
    移除用户
    URL: /api/remove/
    Method: POST
    Permission: 管理员
    Permission: 登录用户
    Param:
        username: 被删除用户名
    """
    if request.method == 'POST':
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        if not (request.user.is_superuser or request.user.is_staff):
            # 权限不足 403
            return HttpResponseForbidden('No permission.')
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        username = query.get('username')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户不存在 400
            return HttpResponseBadRequest('User does not exist.')
        if user.is_superuser:
            # 权限不足 403
            return HttpResponseForbidden('Unauthorized.')
        if user.is_staff and not request.user.is_superuser:
            # 权限不足 403
            return HttpResponseForbidden('Unauthorized.')
        user.delete()
        return HttpResponse()
    return HttpResponseNotFound()


def set_staff(request):
    """
    修改用户管理员权限
    URL: /api/set_staff/
    Method: POST
    Permission: 超级管理员
    Param:
        username: 被修改用户名
        flag: true-设置 false-取消
    """
    if request.method == 'POST':
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        if not request.user.is_superuser:
            # 权限不足 403
            return HttpResponseForbidden('No permission.')
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        username = query.get('username')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户不存在 400
            return HttpResponseBadRequest('User does not exist.')
        flag = query.get('flag')
        try:
            user.is_staff = flag
            user.save()
            return HttpResponse()
        except ValueError:
            # 参数错误 400
            return HttpResponseBadRequest()
    return HttpResponseNotFound()


def set_detail(request):
    """
    修改用户信息
    URL: /api/get_detail/
    Method: POST
    Permission: 登录用户
    Param:
        id: 游戏id 选填
        level: 等级 选填
    """
    if request.method == 'POST':
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        try:
            query = json.loads(request.body)
        except json.decoder.JSONDecodeError:
            # 参数错误 400
            return HttpResponseBadRequest()
        uid = query.get('id')
        level = query.get('level')
        try:
            if uid:
                if len(uid) < 16:
                    request.user.uid = uid
                else: raise ValueError
            if level:
                if level < 999:
                    request.user.level = level
                else: raise ValueError
        except ValueError:
            # 参数错误 400
            return HttpResponseBadRequest()
        request.user.save()
        return HttpResponse()
    return HttpResponseNotFound()


def get_detail(request):
    """
    获取用户信息
    URL: /api/get_detail/
    Method: POST
    Permission: 登录用户
    """
    if request.method == 'POST':
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        return HttpResponse(json.dumps(request.user.detail))
    return HttpResponseNotFound()


def get_detail_all(request):
    """
    获取所有用户信息
    URL: /api/get_detail_all/
    Method: POST
    Permission: 登录用户
    Return: {
        username: string, // 用户名
        id: string, // 游戏id
        level: number, // 等级
        box: {
            id: string, // 人物id
            rank: number,
            star: number,
            max: boolean  // 是否满强
        }[]
    }[]
    """
    if request.method in ('POST', 'GET'):
        if not request.user.is_authenticated:
            # 未登录 401
            return HttpUnauthorized('Unauthorized.')
        detail = [
            i.detail for i in User.objects.all()
        ]
        return HttpResponse(json.dumps(detail))
    return HttpResponseNotFound()