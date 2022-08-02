from enum import unique
from flask  import Flask, render_template, request, redirect, url_for,jsonify
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from flask_admin import Admin
from  flask_login import UserMixin, LoginManager, login_required, login_user, logout_user,current_user
import os 
from random import randint
from datetime import datetime
from werkzeug.security  import generate_password_hash, check_password_hash
from flask_admin.contrib.sqla import ModelView

#Position all of this after the db and app have been initialised


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname((__file__)))
database = "app.db"
con = sqlite3.connect(os.path.join(basedir,database))
app.config['SECRET_KEY'] = "jhkxhiuydu"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir,database)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'

db = SQLAlchemy(app)


#creating your table

class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(500), unique=True)
    firstname = db.Column(db.String(500))
    lastname = db.Column(db.String(500))
    password = db.Column(db.String(500))
    is_admin = db.Column(db.Boolean, default = False)
    

    def check_password(self, password):
        return check_password_hash(self.password, password)
    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')


    def create(self, username='',  email='', firstname='', password='',lastname=''):
        self.username	 = username
        self.email	 = email
        self.firstname 	 = firstname
        self.lastname = lastname
        self.password= generate_password_hash(password, method='sha256')


    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()
        
        
        
        
class Settings(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(255), unique=True)
    lastname = db.Column(db.String(255), unique=True)
    
    
class Secure(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    def not_auth(self):
        return "not allowed"
    #creating the admin dashboard
    
admin = Admin(app, name='administration', template_mode='bootstrap3')
admin.add_view(Secure(Users, db.session))
admin.add_view(Secure(Settings, db.session))


login_manager = LoginManager()
login_manager.login_view = "signin"
login_manager.init_app(app)
@login_manager.user_loader
def user_loader(user_id):
    return Users.query.get(user_id)




#routing

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login',methods=['GET','POST'])
def login():
    user = Users()
    if request.method == 'POST':
        username = request.form['usernames']
        password = request.form['passwords']
        user = Users.query.filter_by(username=username,is_admin=True).first()
       
        if user:
            if user.password == password:
                login_user(user)
                return redirect('admin')

                
                
            


    return render_template('login.html')
@app.route('/process',methods=['GET','POST'])

def process():
    auths = Users()
    if request.method == "POST":
        username = request.form['uname']
        password = request.form['pass']
        email = request.form['email']
        auths = Users(username=username,
             password=password,email=email,is_admin=True)
        db.session.add(auths)
        db.session.commit()
        return "welcome sign up completed"
    return render_template('register.html')




@app.route("/dashboard")
@login_required
def dashboard():
    siteSettings = Settings.query.all()
  
    return render_template('dashboard.html',
                                siteSettings=siteSettings,
                                )
@app.route('/profile',methods=['GET','POST'])
@login_required
def profile():
    siteSettings = Settings.query.all()
    return render_template('profile.html',siteSettings=siteSettings)

@app.route("/signin",methods=['GET','POST'])
def signin():
    users = Users()
    if request.method == "POST":
        data = request.json
        userByusername = users.query.filter_by(username=data['username']).first()
        userByemail = users.query.filter_by(email=data['username']).first()
        mainUser = None
     
        if userByusername:
            mainUser = userByusername
        if userByemail:
            mainUser = userByemail
        if mainUser:
            if mainUser.check_password(data['password']):
                login_user(mainUser,remember=True,fresh=True)
                return jsonify({'status':200,'msg':'user authenticated'})
            return jsonify({"status":404,"msg":"Inavlid password provided!!!"})
        return jsonify({"status":404,"msg":"invalid email or username"})

    return render_template("signin.html")


@app.route("/signup",methods=['GET','POST'])
def signup():
    users = Users()
    if request.method == 'POST':
        data = request.json
        username = data['username']
        email = data['email']
        firstname = data['firstname']
        lastname = data['lastname']
        password = data['password']
        if users.query.filter_by(username=username).first():
            return jsonify({"status":404,"msg":"username already exist!!!"})
        if users.query.filter_by(email=email).first():
            return jsonify({"status":404,"msg":"email already exist!!!"})
        users.create(username=username,
                            email=email,
                            firstname = firstname,
                            lastname = lastname,
                            password = password
                            )
        users.save()

        login_user(users)
        # return redirect(url_for("dashboard"))
        return jsonify({'status':200,"msg":"registration compelete!!!"})

    return render_template("signup.html")



@app.route("/updatepassword",methods=['POST'])
def updatepassword():
    data = request.json
    if check_password_hash(current_user.password,data['currentpassword']):
        current_user.password = data['newpassword']
        Users.commit()
        return jsonify({'status':200,'msg':'password reset complete'})
    return jsonify({'status':404,'msg':'password not match'})
@app.route("/verify",methods=['POST'])
def verify():
    request.files['file']
    current_user.verified = True
    db.session.commit()
    return redirect(url_for('dashboard'))



@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("signin"))

@app.route("/db")
def database():
    db.drop_all()
    db.create_all()
    return "Hello done!!!"
    

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8000, debug=True)