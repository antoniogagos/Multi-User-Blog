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
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    like = db.IntegerProperty()
    likers = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')

        return render_str("post.html", p=self)

class AddComment(db.Model):
    comment = db.ReferenceProperty(Post, collection_name='comment_post')
    comment_type = db.TextProperty(required=True)
    comment_user = db.IntegerProperty(required=True)


# Creates the antecedent element in the database to store all users
# passing parameter to have user groups
def users_key(group='default'):
    return db.Key.from_path('users', group)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        # get_by_id = Retrieves the model instance for the given numeric ID
        # Model.get_by_id (ids, parent=None)
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        # Replace select * from user where name = name
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    # Creates a new user object only creates the new user it doesn't actually
    # store it in database yet.
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
