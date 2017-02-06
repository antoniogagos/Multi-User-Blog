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

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

## Random string used as hash secret for cookies
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

    ## Sets a cookie(name, val).  Calls make_secure_val on the val given
    ## and then it stores that in a cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        ## No expires time included so by default will expire when browser is closed
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    ## Reading a secure cookie. (name = cookie) and if finds that cookie(name) in the request
    ## passes check_secure_val and returns cookie_val
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    ## Sets the cookie for the unique user
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    ## Gets called before every request by the App Engine framework
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        ## check for the user cookie and if it exists store in self.user the actual
        ## user object
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

## Render blog posts in front page ordereb by date creation
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts)


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

## Creates the antecedent element in the database to store all users
## passing parameter to have user groups
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

## Inherits from db_model that's what makes it a data store object
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    ## Decorator - First parameter cls = referring to this Class user not an
    ## actual instance of a user. - Second parameter = user ID
    @classmethod
    def by_id(cls, uid):
        ## get_by_id = Retrieves the model instance for the given numeric ID
        ## Model.get_by_id (ids, parent=None)
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        ## Replace select * from user where name = name
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    ## Creates a new user object only creates the new user it doesn't actually
    ## store it in database yet.
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

## Create Post entity and define its columns
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    user = db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    like = db.IntegerProperty()
    likers = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')

        return render_str("post.html", p = self)


## Getting post id and rendering it on the site
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        button_clicked = self.request.get("action")

        if self.user:
            user_id = self.user.key().id()

            ## Check which button did user clicked and then perform in accordance with the button clicked
            if button_clicked == "like":
                if post.user != user_id:
                    userStr = str(user_id)
                    if userStr not in post.likers:
                        post.likers.append(userStr)
                        likeCount = post.like + 1
                        post.like = likeCount
                        self.render("permalink.html", post = post)
                        post.put()
                    else:
                        self.render("permalink.html", post = post)
                else:
                    error = "You cannot like your own post"
                    self.render("permalink.html", post = post, error = error)

            elif button_clicked == "unlike":
                if post.user != user_id:
                    userStr = str(user_id)
                    if userStr not in post.likers:
                        post.likers.append(userStr)
                        likeCount = post.like - 1
                        post.like = likeCount
                        self.render("permalink.html", post = post)
                        post.put()
                    else:
                        self.render("permalink.html", post = post)
                else:
                    error = "You cannot unlike your own post."
                    self.render("permalink.html", post = post, error = error)

            elif button_clicked == "edit":

                if post.user == user_id:
                    self.redirect('/blog/editpost/%s' % post_id)
                else:
                    error = "You cannot edit this post!"
                    self.render("permalink.html", post = post, error = error)

            elif button_clicked == "delete":
                if post.user == user_id:
                    post.delete()
                    self.redirect("/")
                else:
                    error = "You cannot delete this post"
                    self.render("permalink.html", post = post, error = error)

            elif button_clicked == "comment":
                content = self.request.get("content")
                AddComment(comment = post, comment_type = content, comment_user = user_id).put()
                self.redirect("/blog/%s" % post_id)

        else:
            self.redirect("/login")

## Reference to the Post model instance in order to create as many comments as user wants
class AddComment(db.Model):
    comment = db.ReferenceProperty(Post, collection_name = 'comment_post')
    comment_type = db.TextProperty(required = True)
    comment_user = db.IntegerProperty( required = True)

class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        ## Loop in all post comments to get the one the user clicked
        for c in post.comment_post:
            if self.user:
                if int(c.key().id()) == int(comment_id):
                    if post.user == self.user.key().id():
                        self.render("permalink-comments.html", c = c, post_id = post_id)
                    else:
                        error = "You cannot edit this comment"
                        self.render("permalink.html", post = post, error = error)
            else: self.redirect("/login")

    def post(self, post_id, comment_id):
        comment = self.request.get('comment')
        if comment:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            for c in post.comment_post:
                if int(c.key().id()) == int(comment_id):
                    c.comment_type = comment
                    c.put()

                    self.redirect('/blog/%s' % post_id)

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        for c in post.comment_post:
            if self.user:
                if int(c.key().id()) == int(comment_id):
                    if post.user == self.user.key().id():
                        self.render("permalink-delete.html", c = c, post_id = post_id, post= post)
                    else:
                        error = "You cannot delete this comment"
                        self.render("permalink.html", post = post, error = error)
            else: self.redirect("/login")

    def post(self, post_id, comment_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        for c in post.comment_post:
            if int(c.key().id()) == int(comment_id):
                c.delete()

                self.redirect('/blog/%s' % post_id)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user = self.user.key().id(), like = 0)
            p.put()

            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)

        if post.user == self.user.key().id():
            subject = post.subject
            content = post.content
            self.render("editpost.html", subject = subject, content = content, p = post)
        else:
            self.redirect("/blog/login")


    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent = blog_key())
            post = db.get(key)
            post.content = content
            post.subject = subject

            post.put()
            self.redirect('/blog/%s' % post_id)

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent = blog_key())
        post = db.get(key)
        if post.user == self.user.key().id():
            post.delete()
            self.redirect("/")
        else:
            error = "You cannot delete this post"
            self.render("permalink.html", post = post, error = error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
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

        params = dict(username = self.username,
                      email = self.email)

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
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
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
            self.render('login-form.html', error = msg)

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
