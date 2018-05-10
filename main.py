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

import webapp2
from webapp2 import Route

from handlers import (MainPage, Login, SignUp, NewPost, Logout, BlogPage, 
                      BlogPost, EditPost, DeletePost, ToggleLike, AddComment,
                      DeleteComment, EditComment)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', Login),
    ('/signup', SignUp),
    ('/newpost', NewPost),
    ('/logout', Logout),
    Route('/b/<name:\w+>', BlogPage),
    Route(r'/b/<name:\w+>/<id:\d+>', BlogPost),
    Route(r'/b/<name:\w+>/<id:\d+>/edit', EditPost),
    Route(r'/b/<name:\w+>/<id:\d+>/delete', DeletePost),
    Route(r'/b/<name:\w+>/<id:\d+>/togglelike', ToggleLike),
    Route(r'/b/<name:\w+>/<id:\d+>/addcomment', AddComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/delete', 
          DeleteComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/edit', 
          EditComment),
], debug=True)
