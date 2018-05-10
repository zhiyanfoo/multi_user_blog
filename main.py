import webapp2
from webapp2 import Route

import handlers as h

app = webapp2.WSGIApplication([
    ('/', h.MainPage),
    ('/login', h.Login),
    ('/signup', h.SignUp),
    ('/logout', h.Logout),
    ('/add_post', h.AddPost),
    Route('/b/<name:\w+>', h.UserPosts),
    Route(r'/b/<name:\w+>/<id:\d+>', h.SinglePost),
    Route(r'/b/<name:\w+>/<id:\d+>/edit', h.EditPost),
    Route(r'/b/<name:\w+>/<id:\d+>/delete', h.DeletePost),
    Route(r'/b/<name:\w+>/<id:\d+>/togglelike', h.ToggleLike),
    Route(r'/b/<name:\w+>/<id:\d+>/addcomment', h.AddComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/delete',
          h.DeleteComment),
    Route(r'/b/<name:\w+>/<id:\d+>/<c_user_name:\d+>/<c_id:\d+>/edit',
          h.EditComment),
], debug=True)
