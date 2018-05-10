import webapp2
from webapp2 import Route

from handlers import (MainPage, Login, SignUp, AddPost, Logout, UserPosts,
                      SinglePost, EditPost, DeletePost, ToggleLike, AddComment,
                      DeleteComment, EditComment)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', Login),
    ('/signup', SignUp),
    ('/logout', Logout),
    ('/add_post', AddPost),
    Route('/b/<name:\w+>', UserPosts),
    Route(r'/b/<name:\w+>/<id:\d+>', SinglePost),
    Route(r'/b/<name:\w+>/<id:\d+>/edit', EditPost),
    Route(r'/b/<name:\w+>/<id:\d+>/delete', DeletePost),
    Route(r'/b/<name:\w+>/<id:\d+>/togglelike', ToggleLike),
    Route(r'/b/<name:\w+>/<id:\d+>/addcomment', AddComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/delete',
          DeleteComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/edit',
          EditComment),
], debug=True)
