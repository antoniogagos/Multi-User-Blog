#coding: utf-8
import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from models import Post
from models import AddComment
from models import User

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Random string used as hash secret for cookies
secret = 'secret:D'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Sets a cookie(name, val).  Calls make_secure_val on the val given
    # and then it stores that in a cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        # No expires time included so by default will expire when browser is closed
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Sets the cookie for the unique user
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Gets called before every request
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        # check for the user cookie and if it exists store in self.user the actual
        # user object
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Render blog posts in front page ordereb by date creation
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


# blog stuff
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

def editPost(self, post):
    user_id = self.user.key().id()
    if post.user == user_id:
        self.redirect('/blog/editpost/%s' % post.key().id())
    else:
        error = "You cannot edit this post!"
        self.render("permalink.html", post=post, error=error)


def likePost(self, post):
    user_id = self.user.key().id()

    if post.user != user_id:

        userStr = str(user_id)
        if userStr not in post.likers:
            post.likers.append(userStr)
            likeCount = post.like + 1
            post.like = likeCount
            self.render("permalink.html", post=post)
            post.put()
        else:
            self.render("permalink.html", post=post)
    else:
        error = "You cannot like your own post"
        self.render("permalink.html", post=post, error=error)


def unlikePost(self, post):
    user_id = self.user.key().id()

    if post.user != user_id:
        userStr = str(user_id)
        if userStr not in post.likers:
            post.likers.append(userStr)
            likeCount = post.like - 1
            post.like = likeCount
            self.render("permalink.html", post=post)
            post.put()
        else:
            self.render("permalink.html", post=post)
    else:
        error = "You cannot unlike your own post."
        self.render("permalink.html", post=post, error=error)


def deletePost(self, post):
    user_id = self.user.key().id()

    if post.user == user_id:
        post.delete()
        self.redirect("/")
    else:
        error = "You cannot delete this post"
        self.render("permalink.html", post=post, error=error)


def commentPost(self, post):
    user_id = self.user.key().id()
    content = self.request.get("content")
    AddComment(comment=post, comment_type=content, comment_user=user_id).put()
    self.redirect("/blog/%s" % post.key().id())


# Getting post id and rendering it on the site
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        button_clicked = self.request.get("action")
        if self.user:
            user_id = self.user.key().id()

            # Check which button did user clicked and then perform in accordance with the button clicked
            if button_clicked == "like":
                likePost(self, post)

            elif button_clicked == "unlike":
                unlikePost(self, post)

            elif button_clicked == "edit":
                editPost(self, post)

            elif button_clicked == "delete":
                deletePost(self, post)

            elif button_clicked == "comment":
                commentPost(self, post)

        else:
            self.redirect("/login")


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        # Loop in all post comments to get the one the user clicked
        for c in post.comment_post:
            if self.user:
                if int(c.key().id()) == int(comment_id):
                    if c.comment_user == self.user.key().id():
                        self.render("permalink-comments.html", c=c, post_id=post_id)
                    else:
                        self.redirect("/blog/%s" % post_id)
            else:
                self.redirect("/login")

    def post(self, post_id, comment_id):
        comment = self.request.get('comment')
        if comment:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            for c in post.comment_post:
                if self.user:
                    if int(c.key().id()) == int(comment_id):
                        c.comment_type = comment
                        c.put()

                        self.redirect('/blog/%s' % post_id)
                else:
                    self.redirect("/login")


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        for c in post.comment_post:
            if self.user:

                if int(c.key().id()) == int(comment_id):
                    if c.comment_user == self.user.key().id():
                        self.render("permalink-delete.html", c=c, post_id=post_id, post=post)
                    else:
                        self.redirect("/blog/%s" % post_id)
            else:
                self.redirect("/login")

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        for c in post.comment_post:
            if self.user:

                if int(c.key().id()) == int(comment_id):
                    c.delete()

                    self.redirect('/blog/%s' % post_id)
            else:
                self.redirect("/login")


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, user=self.user.key().id(), like=0)
            p.put()

            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post.user == self.user.key().id():
            subject = post.subject
            content = post.content
            self.render("editpost.html", subject=subject, content=content, p=post)
        else:
            self.redirect("/login")

    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post.user == self.user.key().id():
            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.content = content
                post.subject = subject

                post.put()
                self.redirect('/blog/%s' % post_id)
        else:
            self.redirect("/login")


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post.user == self.user.key().id():
            post.delete()
            self.redirect("/")
        else:
            error = "You cannot delete this post"
            self.render("permalink.html", post=post, error=error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/([0-9]+)/([0-9]+)', EditComment),
                               ('/blog/delete/([0-9]+)/([0-9]+)', DeleteComment),
                               ],
                              debug=True)
