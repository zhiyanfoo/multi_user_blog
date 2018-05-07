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

import webapp2
from webapp2 import Route
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class TestHandler(webapp2.RequestHandler):
    def post(self):
        q = self.request.get("q")
        self.response.out.write(self.request)


class Post(db.Model):
    title = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @staticmethod
    def to_tuple(p):
        return (p.title, p.post, p.created.date(), p.key().id()) 


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("index.html", blogs=posts)


class NewPost(Handler):
    def render_front(self, title="", post="", error=""):
        self.render("new_post.html", title=title, post=post, error=error)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        post = self.request.get("post")
        error = ""
        if title and post:
            p = Post(title=title, post=post)
            p.put()
            self.redirect("/")
        else:
            self.render_front(title=title, post=post, error=error)


class BlogPost(Handler):
    def get(self, id):
        self.render("blog_post.html", p=Post.get_by_id(int(id)))


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewPost),
    ('/testform', TestHandler),
    Route(r'/blog<id:\d+>', BlogPost),
], debug=True)
