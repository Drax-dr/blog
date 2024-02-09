import os, base64
import flask
from os.path import join, dirname, realpath
from functools import wraps
import jwt
from flask_cors import CORS
from werkzeug.security import generate_password_hash,check_password_hash
from flask import request, redirect, jsonify, render_template, url_for, flash
from flask_login import LoginManager, login_required, UserMixin, login_user, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import datetime

login_manager = LoginManager()

app = flask.Flask(__name__,static_folder='static',template_folder='templates')
# app.config['CORS_HEADERS'] = 'Content-Type'
app.config["SECRET_KEY"] = 'abcdefghijklmnopqrstuvwxyz'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["JSON_PRETTY_PRINT_REGULAR"] = True
app.config['UPLOAD_FOLDER'] = 'static/images/'
login_manager.init_app(app=app)
CORS(app, resources={r'/*': {'origins': '*'}})
db = SQLAlchemy(app=app)
ma = Marshmallow(app=app)
CUR_DATE = datetime.datetime.today().date()

class Admin(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False, unique=True)
    date_joined = db.Column(db.Date, default=datetime.datetime.utcnow)
    image = db.Column(db.String(120))
    about = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(120), unique=True)
    posts = db.relationship('Posts', backref='author', lazy='dynamic')
    
    def is_authenticated(self):
        return self._authenticated

    def set_password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        print(password)
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return "<User :%s>" % self.username
    
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False, unique=True)
    content = db.Column(db.Text, nullable=False, unique=True)
    date_posted = db.Column(db.Date, default=datetime.datetime.today().date())
    image = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(20), nullable=False, unique=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)

    def __repr__(self) -> str:
        return f"Posts('{self.title}', '{self.content}','{self.image}', '{self.date_posted}', '{self.admin_id}')"

class PostSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Posts
        load_instance = True

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        elif request.args.get('token') is not None:
            token = request.args.get('token')
        if not token:
            return jsonify({"message":"Token is missing"}), 403
        try:
            data = jwt.decode(jwt=token, key=app.config["SECRET_KEY"], algorithms=["HS256"])
            user = Admin.query.filter_by(username=data['user']).first()
            admin_id = user.id
        except:
            return jsonify({"message":"Token is Invalid"}), 403
        return f(admin_id,**kwargs)

    return decorated

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(user_id)

@app.route("/")
def home():
    all_posts = db.session.query(Posts).order_by(Posts.date_posted.desc())
    return render_template("index.html", post=all_posts, title="Home",now=CUR_DATE)

@app.route("/p/<slug>")
def get_by_slug(slug):
    blog = db.session.query(Posts).filter_by(slug=slug).first()
    return render_template("post.html",post=blog,title=blog.title)

@app.route("/a/<uname>")
def admin_view(uname):
    admin = db.session.query(Admin).filter_by(username=uname).first()
    posts = db.session.query(Posts).filter_by(admin_id=admin.id).order_by(Posts.date_posted.desc()).all()
    return render_template("admin_page.html",admin=admin,title=admin.username,posts=posts ,now=CUR_DATE)

'''
@app.route("/api/search")
def search():
    search = request.args.get('q')
    search = "%{}%".format(search)
    posts = Posts.query.filter(Posts.title.like(search)).all()
    print(search)
    print(posts)
    data = PostSchema().dump(posts, many=True)
    return jsonify(results=data)
'''
@app.route("/api/")
@token_required
def api_get(admin_id):
    admin = db.session.query(Admin).filter_by(id=admin_id).first()
    all_posts = Posts.query.filter_by(admin_id=admin.id)
    data = PostSchema().dump(all_posts, many=True)
    return jsonify(data)

@app.route("/api/p/<int:pg_id>")
@token_required
def get(admin_id,pg_id):
    admin = db.session.query(Admin).filter_by(id=admin_id).first()
    print(pg_id)
    blog = Posts.query.get(pg_id)
    if blog is not None:
        if blog.admin_id == admin.id:
            data = PostSchema().dump(blog)
            return jsonify(data)
        return jsonify({"error":"Post not found"})
    return jsonify({"error":"Post not found"})

@app.route("/add", methods = ['GET','POST'])
@login_required
def add():
    if not current_user.is_authenticated:
        return  redirect(url_for('login'))
    if request.method == "POST":
        pid = base64.b64encode(os.urandom(32))[:10].decode('utf-8')
        slug = pid.replace('/','')
        title = request.form["title"]
        image = request.files.get('img')
        path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(path)
        print(path)
        Post = Posts(
            title = title,
            content = request.form["content"],
            image = path,
            slug = slug,
            author = current_user
            )
        db.session.add(Post)
        db.session.commit()
        return redirect(url_for('get_by_slug', slug=pid))
    return render_template("add.html")

@app.route("/api/add", methods = ['POST'])
@token_required
def api_add():
    if request.method == "POST":
        pid = base64.b64encode(os.urandom(32))[:10].decode('utf-8')
        slug = pid.replace('/','')
        title = request.form["title"]
        image = request.files['image']
        print(image.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(path)
        print(path)
        Post = Posts(
            title = title,
            content = request.form["content"],
            image = path,
            slug = slug,
            author = current_user
            )
        db.session.add(Post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add.html")

@app.route("/api/d/<slug>", methods = ['DELETE'])
@login_required
def delete(slug):
    if not current_user.is_authenticated:
        return  redirect(url_for('login'))
    blog = db.session.query(Posts).filter_by(slug=slug).first()
    if current_user.id == blog.admin_id:
        db.session.delete(blog)
        db.session.commit()
        return redirect("/")
    return redirect(url_for('home'))

@app.route("/api/e/<slug>", methods = ['GET','POST'])
@login_required
def update(slug):
    if not current_user.is_authenticated:
        return  redirect(url_for('login'))
    blog = db.session.query(Posts).filter_by(slug=slug).first()
    if current_user.id == blog.admin_id:
        if request.method == "POST":
            blog.title = request.form["title"]
            blog.content = request.form["content"]
            image = request.files['image']
            path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
            blog.image = path
            db.session.commit()
            return redirect(url_for('home'))
        return render_template("edit_post.html",post=blog)
    return redirect(url_for('home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.query(Admin).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            next = request.args.get("next")
            token = jwt.encode({"user":username,"exp":datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},key=app.config['SECRET_KEY'])
            user.api_token = token
            print(token)
            db.session.commit()
            flash('Login successfully.', 'success')
            print(next)
            if next:
                return redirect(next)
            return redirect(url_for("home"))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html', title="Login")

@app.route('/api/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
