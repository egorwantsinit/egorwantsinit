from multiprocessing import Barrier
from typing import Optional
from unicodedata import name
from urllib import response
from click import password_option
from fastapi import FastAPI, Form, Cookie, Body
#Для отправки ответа в браузер
from fastapi.responses import Response

import hmac
import hashlib
import base64
import json

#экземпляр приложения FastAPI
app = FastAPI() 

SECRET_KEY = "51d8f1b0c6990bf117ef62a75d0ec1ca4a60f3f2bf8fbc2758d6b5489c7c7351"
PASSWORD_SALT  = "e4847ab07840554a7e31c71298e45d59b07985132b444f45052279917ced9c1d"



# функция по подписи данных
def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(), 
        msg = data.encode(),
        digestmod = hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    "Сравниваем хэш с солью с хэшом пароля в базе данных"
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return  password_hash == stored_password_hash


#добавим возможноть выводить страничку

#login_page = """
#<html>
#<head>
#<title>Логин</title>
#<meta charset="utf-8" />
#</head>
#<body>
#Привет, <strong>мир</strong>!
#</body>
#</html>
#""" # это у наас перенос строки. Он есть и в начале
 #(этот html перенесен в отдельный файл login.html)


"""@app.get("/") #задание когда будет вызываться функция 
def index_page(): #функция для обработки http-запроса
    return Response(login_page, media_type= "text/html")"""

#создадим словарь пользователей для проверки
# в реальных проектах пользуются БД

users = {
    "egor@user.com": {
        "name" : "Егор",
        "password" : "1f658e5c5b79bd6b9c7698ad412a2a45afd85ee5d0e2b3d336d7883432ed11f2",
        "balance" : 100_000
    },
    "petr@user.com" : {
        "name" : "Петр",
        "password" : "4e1c76cc42e4c315197543c7dd0cd94754fc314fef7eb75f2d900d12d8e02b11",
        "balance" : 555_555        
    }
}


@app.get("/") #задание когда будет вызываться функция 
def index_page(username: Optional[str] = Cookie(default=None)): #функция для обработки http-запроса
    with open('templates/login.html', 'r') as f: #читаем файл login.html
        login_page = f.read()
    if not username:
        return Response(login_page, media_type= "text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type= "text/html")
        response.delite_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type="text/html")
        response .delite_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"\
        f"Баланс: {users[valid_username]['balance']}", 
        media_type= "text/html")


"""Запуск сервера в Debian: 
uvicorn server:app --reload

заходим в браузер на localhost:8000
"""
@app.post('/login')
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    print("user is", user, "password is", password)
    if not user or verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}!<br />Баланс: {user['balance']}",
        }),
        media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." +\
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response