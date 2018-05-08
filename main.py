# -*- coding: utf-8 -*-

# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import hashlib
import re
from datetime import timedelta, datetime
import random
from functools import partial

import webapp2
from webapp2 import Route
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Post(db.Model):
    title = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    pw_hash = db.StringProperty(required=True)
    pw_salt = db.StringProperty(required=True)
    cookie_hash = db.StringProperty(required=True)
    cookie_salt = db.StringProperty(required=True)
    cookie_datetime = db.DateTimeProperty(required=True, auto_now=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookies(self, username, cookie_token):
        expires = datetime.now() + timedelta(days=2) 
        self.response.set_cookie('username', username, expires=expires)
        self.response.set_cookie('token', cookie_token, expires=expires)

    def clear_cookies(self):
        self.response.set_cookie('username', "")
        self.response.set_cookie('token', "")

    def valid_user(self):
        username = self.request.cookies.get('username')
        if not username:
            return
        token_ck = self.request.cookies.get('token')
        user = User.get_by_key_name(username)
        if user:
            hash_result, _ = secret_salt(token_ck, user.cookie_salt)
            if hash_result == user.cookie_hash:
                return user

    def get_user(self, name):
        if name:
            return User.get_by_key_name(name)

    def get_cur_user_name(self):
        cur_user = self.valid_user()
        cur_user_name = cur_user.key().name() if cur_user else None
        return cur_user_name

    def user_owns_page(self, page_user_name):
        return self.valid_user().key().name() == page_user_name


    def render_posts(self, page_user, cur_user_name=None):
        q = db.Query(Post)
        page_user_key = page_user.key()
        q.ancestor(page_user_key)
        q.order('-created')
        self.render("posts.html", blogs=q, page_user=page_user_key.name(),
                    username=cur_user_name)

class NewPost(Handler):
    def render_front(self, username, title="", post="", error="", ):
        self.render("new_post.html", username=username, title=title, post=post,
                    error=error, page_user=username)

    def get(self):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
        self.render_front(user.key().name())

    def post(self):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
            return
        title = self.request.get("title")
        post = self.request.get("post")
        if not (title and post):
            self.render_front(
                user.key().name(),
                title=title, 
                post=post, 
                error="Error: All fields need to be filled.")
            return
        p = Post(title=title, post=post, parent=user)
        p.put()
        self.redirect("/")

class BlogPost(Handler):
    def get(self, name, id):
        cur_user_name = self.get_cur_user_name()
        page_user = self.get_user(name)
        p = Post.get_by_id(int(id), parent=page_user.key())
        self.render("blog_post.html", p=p, page_user=name, username=cur_user_name)

    def post(self, name, id):
        if self.user_owns_page(name):
            page_user = self.get_user(name)
            p = Post.get_by_id(int(id), parent=page_user.key())
            p.delete()
            self.redirect("/b/" + name)
        else:
            self.clear_cookies()
            self.redirect("/")
        

class HomePage(Handler):
    def get(self):
        user = self.valid_user()
        if user:
            self.redirect("/b/" + user.key().name())
        else:
            self.render("unknown_user.html")

class Posts(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("index.html", blogs=posts)

class Login(Handler):
    def err_render(self, username, msg):
        self.clear_cookies()
        self.render("unknown_user.html", 
                    login_username=username, 
                    err_msg1="Error: " + msg)

    def post(self):
        username = self.request.get("login_username")
        password = self.request.get("login_password")
        err_render = partial(self.err_render, username)
        if not (username and password):
            err_render("fill all login fields")
            return
        
        user = User.get_by_key_name(username)
        if not user:
            err_render("username not found")
            return 

        pw_hash, _ = secret_salt(password, user.pw_salt)
        if pw_hash != user.pw_hash:
            err_render("password invalid")
            return
        
        cookie_token, user_secrets = new_secrets(password)
        for name, value in user_secrets.items():
            setattr(user, name, value)
        user.put()
        expires = datetime.now() + timedelta(days=2) 
        self.set_cookies(username, cookie_token)
        self.redirect("/")

class SignUp(Handler):
    def err_render(self, username, msg):
        self.clear_cookies()
        self.render("unknown_user.html", 
                    signup_username=username,
                    err_msg2="Error: " + msg)

    def post(self):
        username = self.request.get("signup_username")
        password1 = self.request.get("signup_password1")
        password2 = self.request.get("signup_password2")
        err_render = partial(self.err_render, username)
        if not (username and password1 and password2):
            err_render("fill all signup fields")
            return

        if not re.match(r"^[a-zA-Z0-9_]{1,24}$", username):
            err_render("username not valid. username"
                       " must be less than 25 characters long"
                       " and only contain characters from this set"
                       " [a-zA-Z0-9_]")
            return

        if password1 != password2:
            err_render("passwords are not equal")
            return

        user = User.get_by_key_name(username)
        if user:
            err_render("username already taken")
            return

        cookie_token, user_secrets = new_secrets(password1)
        User(key_name=username, **user_secrets).put()
        self.set_cookies(username, cookie_token)
        self.redirect("/")

class Logout(Handler):
    def post(self):
        self.clear_cookies()
        self.redirect("/")

class BlogPage(Handler):
    def get(self, name):
        page_user = self.get_user(name)
        cur_user_name = self.get_cur_user_name()
        if page_user:
            self.render_posts(page_user, cur_user_name)
        else:
            self.write("404: Blog not found.")

class EditPost(Handler):
    def render_front(self):
        pass

    def post(self, name, id):
        if not self.user_owns_page(name):
            self.clear_cookies()
            self.redirect('/')
        page_user = self.get_user(name)
        p = Post.get_by_id(int(id), parent=page_user.key())
        name = page_user.key().name()

        title = self.request.get("title")
        post = self.request.get("post")
        if not title and not post:
            self.render(
                "editpost.html",
                title=p.title, 
                post=p.post,
                page_user=name,
                p=p, 
                username=name)
            return

        if not (title and post):
            self.render(
                "editpost.html",
                title=title, 
                post=post,
                page_user=name,
                p=p, 
                username=name,
                error="Error: All fields need to be filled.")
            return

        p.title = title
        p.post = post
        p.put()
        self.redirect("/b/"+ name + "/" + id)




def new_secrets(pw):
    pw_hash, pw_salt = secret_salt(pw)
    cookie_token = make_token()
    cookie_hash, cookie_salt = secret_salt(cookie_token)
    user_secrets = {
        "pw_hash": pw_hash,
        "pw_salt": pw_salt,
        "cookie_hash": cookie_hash,
        "cookie_salt": cookie_salt,
    }
    return cookie_token, user_secrets

def make_token():
    return "".join(str(random.SystemRandom().randint(0,26)) for _ in range(16))

def secret_salt(s, salt=None):
    if not salt:
        salt = make_token()
    return hashlib.sha256(s + salt).hexdigest(), salt

def valid_pw(pw, salt, h):
    pw_hash = secret_salt(pw, salt)
    return pw_hash == h

app = webapp2.WSGIApplication([
    ('/', HomePage),
    ('/login', Login),
    ('/signup', SignUp),
    ('/newpost', NewPost),
    ('/logout', Logout),
    Route('/b/<name:\w+>', BlogPage),
    Route(r'/b/<name:\w+>/<id:\d+>', BlogPost),
    Route(r'/b/<name:\w+>/<id:\d+>/edit', EditPost),
], debug=True)
