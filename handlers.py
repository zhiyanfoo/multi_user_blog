import os
import jinja2
import webapp2
import re

from models import Post, User, Comment 
from helpers import new_secrets, secret_salt
from google.appengine.ext import db
from datetime import timedelta, datetime
from functools import partial
import urllib

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

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
        return User.get_by_key_name(name) if name else None

    def get_user_name(self, user):
        return user.key().name() if user else None

    def cur_user_match(self, user_name):
        return self.valid_user().key().name() == user_name

    def has_liked(self, user, post):
        q = db.Query(User)
        q.filter("__key__ =", user.key())
        q.filter("liked =", post.key())
        return q.get()

    def get_post(self, user, id):
        return Post.get_by_id(int(id), parent=user.key())


class NewPost(Handler):
    def render_front(self, username, title="", post="", error="", ):
        self.render("new_post.html", username=username, title=title, post=post,
                    error=error, page_user_name=username)

    def get(self):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
            return
        
        self.render_front(user.key().name())

    def post(self):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
            return

        title = self.request.get("title").strip()
        post = self.request.get("post").strip()
        if not (title and post):
            self.render_front(
                user.key().name(),
                title=title, 
                post=post, 
                error="All fields need to be filled.")
            return

        p = Post(title=title, post=post, parent=user)
        p.put()
        self.redirect("/")

class BlogPost(Handler):
    def get(self, name, id):
        user = self.valid_user()
        cur_user_name = self.get_user_name(user)
        page_user = self.get_user(name)
        if not page_user:
            self.redirect("/")
            return

        p = self.get_post(page_user, id)
        if not p:
            self.write("Post does not exist")
            return

        liked = self.has_liked(user, p) if user else None
        c = db.Query(Comment)
        post_key = p.key()
        c.ancestor(post_key)
        c.order('-created')
        self.render("post.html", comments=c, p=p, page_user_name=name,
                    username=cur_user_name, liked=liked)

class MainPage(Handler):
    def get(self):
        user = self.valid_user()
        if user:
            self.redirect("/b/" + user.key().name())
        else:
            self.render("unknown_user.html")

class LoginSignup(Handler):
    def get(self):
        login_username = self.request.get("entered_login_username")
        signup_username = self.request.get("entered_signup_username")
        err_msg1 = self.request.get("err_msg1")
        err_msg2 = self.request.get("err_msg2")
        self.render("unknown_user.html", 
                    login_username=login_username,
                    signup_username=signup_username,
                    entered_login_username=login_username,
                    entered_signup_username=signup_username,
                    err_msg1=err_msg1,
                    err_msg2=err_msg2)

class Login(LoginSignup):
    def err_render(self, username, msg):
        self.clear_cookies()
        parameters = urllib.urlencode(
            {'entered_login_username': username,
             'err_msg1': msg})
        url = '/login?' + parameters
        self.redirect(url)

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

class SignUp(LoginSignup):
    def err_render(self, username, msg):
        self.clear_cookies()
        parameters = urllib.urlencode(
            {'entered_signup_username': username,
             'err_msg2': msg})
        url = '/signup?' + parameters
        self.redirect(url)

    def post(self):
        username = self.request.get("signup_username")
        password = self.request.get("signup_password")
        password_confirm = self.request.get("signup_password_confirm")
        err_render = partial(self.err_render, username)
        if not (username and password and password_confirm):
            err_render("fill all signup fields")
            return

        if not re.match(r"^[a-zA-Z0-9_]{1,24}$", username):
            err_render("username not valid. username"
                       " must be less than 25 characters long"
                       " and only contain characters from this set"
                       " [a-zA-Z0-9_]")
            return

        user = User.get_by_key_name(username)
        if user:
            err_render("username already taken")
            return

        if password != password_confirm:
            err_render("passwords are not equal")
            return

        cookie_token, user_secrets = new_secrets(password)
        User(key_name=username, **user_secrets).put()
        self.set_cookies(username, cookie_token)
        self.redirect("/")

class Logout(Handler):
    def post(self):
        self.clear_cookies()
        self.redirect("/")

class BlogPage(Handler):
    def get(self, name):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
            return
        cur_user_name = self.get_user_name(user)
        page_user = self.get_user(name)
        if page_user:
            q = db.Query(Post)
            page_user_key = page_user.key()
            q.ancestor(page_user_key)
            q.order('-created')
            postsliked = [(p, self.has_liked(user, p)) for p in q]
            self.render("posts.html", postsliked=postsliked,
                        page_user_name=page_user_key.name(),
                        username=cur_user_name)
        else:
            self.write("404: Blog not found.")

class EditPost(Handler):
    def post(self, name, id):
        if not self.cur_user_match(name):
            self.clear_cookies()
            self.redirect('/')
        page_user = self.get_user(name)
        p = self.get_post(page_user, id)
        name = page_user.key().name()

        title = self.request.get("title")
        post = self.request.get("post")
        if not title and not post:
            self.render(
                "editpost.html",
                title=p.title, 
                post=p.post,
                page_user_name=name,
                p=p, 
                username=name)
            return

        if not (title and post):
            self.render(
                "editpost.html",
                title=title, 
                post=post,
                page_user_name=name,
                p=p, 
                username=name,
                error="All fields need to be filled.")
            return

        p.title = title
        p.post = post
        p.put()
        self.redirect("/b/"+ name + "/" + id)

class DeletePost(Handler):
    def post(self, name, id):
        if self.cur_user_match(name) and self.request.get("delete"):
            page_user = self.get_user(name)
            p = self.get_post(page_user, id)
            post_comments_q = db.Query(Comment)
            for comment in post_comments_q.ancestor(p.key()):
                comment.delete()
            for user_key in p.liked_users:
                user = User.get(user_key)
                user.liked.remove(p.key())
                user.put()

            p.delete()
            self.redirect("/b/" + name)
        else:
            self.clear_cookies()
            self.redirect("/")

class ToggleLike(Handler):
    def post(self, name, id):
        cur_user = self.valid_user()
        page_user = self.get_user(name)
        if not (cur_user and page_user):
            self.clear_cookies()
            self.redirect("/")
            return

        p = self.get_post(page_user, id)
        if cur_user.key() != page_user.key():
            if self.has_liked(cur_user, p):
                cur_user.liked.remove(p.key())
                cur_user.put()
                p.liked_users.remove(cur_user.key())
                p.likes -= 1
                p.put()
            else:
                cur_user.liked.append(p.key())
                cur_user.put()
                p.liked_users.append(cur_user.key())
                p.likes += 1
                p.put()

        self.redirect(self.request.referer)

class AddComment(Handler):
    def post(self, id, name):
        cur_user = self.valid_user()
        if not cur_user:
            self.redirect('/')
            return
        cur_user_name = self.get_user_name(cur_user)
        page_user = self.get_user(name)
        post = self.get_post(page_user, id)
        Comment(comment=self.request.get("comment"), 
                user=cur_user_name,
                parent=post).put()
        self.redirect(self.request.referer)

class DeleteComment(Handler):
    def post(self, id, name, c_user_name, c_id):
        if self.cur_user_match(c_user_name):
            page_user = self.get_user(name)
            post = self.get_post(page_user, id)
            comment = Comment.get_by_id(int(c_id), parent=post.key())
            comment.delete()
            self.redirect(self.request.referer)
        else:
            self.clear_cookies()
            self.redirect("/")

class EditComment(Handler):
    def post(self, id, name, c_user_name, c_id):
        if not self.cur_user_match(name):
            self.clear_cookies()
            self.redirect('/')

        cur_user = self.valid_user()
        cur_user_name = self.get_user_name(cur_user)
        page_user = self.get_user(name)
        p = self.get_post(page_user, id)
        c = Comment.get_by_id(int(c_id), parent=p.key())
        comment = self.request.get("comment")
        if not comment:
            self.render("editcomment.html", 
                        c=c,
                        page_user_name=name,
                        liked=self.has_liked(cur_user, p),
                        p=p,
                        username=cur_user_name)
            return

        c.comment = comment
        c.put()
        self.redirect("/b/{}/{}".format(name, id))
