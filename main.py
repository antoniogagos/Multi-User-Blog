import os
import webapp2
import jinja2

from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        ##params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts = posts)


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')

        return render_str("post.html", p = self)

class NewPost(BlogHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            print(p.key().id())
            self.redirect('/%s' % str(p.key().id()))


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        ##print(key.id())

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)


class EditPost(NewPost):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        key_id = key.id()
        q = Post.gql("WHERE key.id() = key_id")
        print(q)

        self.render("editpost.html", editSubject = post.subject,
                editContent = post.content)

    def post(self, post_id):
        editedSubject = self.request.get('subject')
        editedContent = self.request.get('content')

        if editedSubject and editedContent:
            p = Post(parent = blog_key(), subject = editedSubject, content = editedContent)
            p.put()
            self.redirect('/')



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPost),
    ('/([0-9]+)', PostPage),
    ('/editpost/([0-9]+)', EditPost),
], debug=True)
