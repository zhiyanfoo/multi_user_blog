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
        return jinja_env.get_template(template).render(params)

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

    def current_user_match(self, user_name):
        user = self.valid_user()
        return user.key().name() == user_name if user else None

    def has_liked(self, user, post):
        q = db.Query(User)
        q.filter("__key__ =", user.key())
        q.filter("liked =", post.key())
        return q.get()

    def get_post(self, user, id):
        return Post.get_by_id(int(id), parent=user.key())


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
        error_msg1 = self.request.get("err_msg1")
        error_msg2 = self.request.get("err_msg2")
        self.render("unknown_user.html",
                    login_username=login_username,
                    signup_username=signup_username,
                    entered_login_username=login_username,
                    entered_signup_username=signup_username,
                    err_msg1=error_msg1,
                    err_msg2=error_msg2)


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


class AddPost(Handler):
    def render_front(self, username, title="", post="", error="", ):
        self.render("add_post.html", username=username, title=title, post=post,
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

        post = Post(title=title, post=post, parent=user)
        post.put()
        self.redirect("/")


class UserPosts(Handler):
    def get(self, name):
        user = self.valid_user()
        if not user:
            self.clear_cookies()
            self.redirect("/")
            return

        current_user_name = self.get_user_name(user)
        page_user = self.get_user(name)
        if page_user:
            q = db.Query(Post)
            page_user_key = page_user.key()
            q.ancestor(page_user_key)
            q.order('-created')
            postsliked = [(post, self.has_liked(user, post)) for post in q]
            self.render("posts.html", postsliked=postsliked,
                        page_user_name=page_user_key.name(),
                        username=current_user_name)
        else:
            self.write("404: Blog not found.")


class SinglePost(Handler):
    def get(self, name, id):
        user = self.valid_user()
        current_user_name = self.get_user_name(user)
        page_user = self.get_user(name)
        if not page_user:
            self.redirect("/")
            return

        post = self.get_post(page_user, id)
        if not post:
            self.write("Post does not exist")
            return

        liked = self.has_liked(user, post) if user else None
        comment_query = db.Query(Comment)
        post_key = post.key()
        comment_query.ancestor(post_key)
        comment_query.order('-created')
        self.render("post.html",
                    comments=comment_query,
                    post=post,
                    page_user_name=name,
                    username=current_user_name,
                    liked=liked)


class EditPost(Handler):
    def get(self, name, id):
        if not self.current_user_match(name):
            self.clear_cookies()
            self.redirect('/')

        page_user = self.get_user(name)
        p = self.get_post(page_user, id)
        name = page_user.key().name()
        self.render(
            "edit_post.html",
            title=p.title,
            post_text=p.post,
            page_user_name=name,
            post=p,
            username=name)

    def post(self, name, id):
        if not self.current_user_match(name):
            self.clear_cookies()
            self.redirect('/')

        page_user = self.get_user(name)
        p = self.get_post(page_user, id)
        name = page_user.key().name()

        title = self.request.get("title")
        post_text = self.request.get("post")
        if not title or not post_text:
            self.redirect("/b/" + name + "/" + id + "/edit")
            return

        p.title = title
        p.post = post_text
        p.put()
        self.redirect("/b/" + name + "/" + id)


class DeletePost(Handler):
    def post(self, name, id):
        if self.current_user_match(name) and self.request.get("delete"):
            page_user = self.get_user(name)
            post = self.get_post(page_user, id)
            post_comments_q = db.Query(Comment)
            for comment in post_comments_q.ancestor(post.key()):
                comment.delete()

            for user_key in post.liked_users:
                user = User.get(user_key)
                user.liked.remove(post.key())
                user.put()

            post.delete()
            self.redirect("/b/" + name)
        else:
            self.clear_cookies()
            self.redirect("/")


class ToggleLike(Handler):
    def post(self, name, id):
        current_user = self.valid_user()
        page_user = self.get_user(name)
        if not (current_user and page_user):
            self.clear_cookies()
            self.redirect("/")
            return

        post = self.get_post(page_user, id)
        if current_user.key() != page_user.key():
            if self.has_liked(current_user, post):
                current_user.liked.remove(post.key())
                current_user.put()
                post.liked_users.remove(current_user.key())
                post.likes -= 1
                post.put()
            else:
                current_user.liked.append(post.key())
                current_user.put()
                post.liked_users.append(current_user.key())
                post.likes += 1
                post.put()

        self.redirect(self.request.referer)


class AddComment(Handler):
    def post(self, id, name):
        current_user = self.valid_user()
        if not current_user:
            self.redirect('/')
            return

        current_user_name = self.get_user_name(current_user)
        page_user = self.get_user(name)
        post = self.get_post(page_user, id)
        comment = self.request.get("comment")
        if not comment:
            self.redirect("/b/{}/{}".format(name, id))
            return

        Comment(comment=self.request.get("comment"),
                user=current_user_name,
                parent=post).put()
        self.redirect(self.request.referer)


class DeleteComment(Handler):
    def post(self, id, name, c_user_name, c_id):
        if self.current_user_match(c_user_name):
            page_user = self.get_user(name)
            post = self.get_post(page_user, id)
            comment = Comment.get_by_id(int(c_id), parent=post.key())
            comment.delete()
            self.redirect(self.request.referer)
        else:
            self.clear_cookies()
            self.redirect("/")


class EditComment(Handler):

    def get(self, id, name, c_user_name, c_id):
        current_user = self.valid_user()
        current_user_name = self.get_user_name(current_user)
        page_user = self.get_user(name)
        post = self.get_post(page_user, id)
        comment = Comment.get_by_id(int(c_id), parent=post.key())
        comment_text = self.request.get("comment")
        self.render("edit_comment.html",
                    c=comment,
                    page_user_name=name,
                    liked=self.has_liked(current_user, post),
                    post=post,
                    username=current_user_name)


    def post(self, id, name, c_user_name, c_id):
        if not self.current_user_match(c_user_name):
            self.clear_cookies()
            self.redirect('/')

        current_user = self.valid_user()
        current_user_name = self.get_user_name(current_user)
        page_user = self.get_user(name)
        post = self.get_post(page_user, id)
        comment = Comment.get_by_id(int(c_id), parent=post.key())
        comment_text = self.request.get("comment")
        if not comment_text:
            self.redirect("/b/{}/{}/{}/{}/edit".format(name, id, c_user_name, c_id))
            return

        comment.comment = comment_text
        comment.put()
        self.redirect("/b/{}/{}".format(name, id))
