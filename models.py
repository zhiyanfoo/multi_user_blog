from google.appengine.ext import db


class Post(db.Model):
    title = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)
    liked_users = db.ListProperty(db.Key)


class User(db.Model):
    pw_hash = db.StringProperty(required=True)
    pw_salt = db.StringProperty(required=True)
    cookie_hash = db.StringProperty(required=True)
    cookie_salt = db.StringProperty(required=True)
    cookie_datetime = db.DateTimeProperty(required=True, auto_now=True)
    liked = db.ListProperty(db.Key)


class Comment(db.Model):
    comment = db.TextProperty(required=True)
    user = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
