import pytest
from flask import g
from flask import session
from wtforms import validators
from wtforms.fields.html5 import EmailField
from wtforms.fields import *

from app.db import get_db


def test_registration(client, application):
    assert client.get("/register").status_code == 200
    response = client.post("/register", data={"email": "a", "password": "a", "confirm": "a"})
    assert "http://localhost/login" == response.headers["Location"]
    with application.app_context():
        assert (
            get_db().execute("SELECT * FROM users WHERE email = 'a'").fetchone()
        )

@pytest.mark.parametrize(
    ("email", "password", "message"),
    (
        ("", "", b"Email required."),
        ("a", "", b"Password required."),
        ("test", "test", b"already registered"),
    ),
)

def test_registration_validate(client, email, password, message):

    email = EmailField('Email Address', [
        validators.DataRequired(),
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=6, max=35)
    ])

    response = client.post(
        "/register", data={"email": email, "password": password}
    )
    assert message in response.data

def test_login(client, auth):
    assert client.get("/login").status_code == 200

    response = auth.login()
    assert response.headers["Location"] == "http://localhost/"

    with client:
        client.get("/")
        assert session["user_id"] == 1
        assert g.user["Email"] == "test"

@pytest.mark.parametrize(
    ("email", "password", "message"),
    (("a", "test", b"Incorrect email."), ("test", "a", b"Incorrect password.")),
)

def test_login_validate(auth, email, password, message):
    email = EmailField('Email Address', [
        validators.DataRequired(),
    ])

    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.length(min=6, max=35)
    ])

    response = auth.login(email, password)
    assert message in response.data

def test_logout(client, auth):
    auth.login()

    with client:
        auth.logout()
        assert "user_id" not in session