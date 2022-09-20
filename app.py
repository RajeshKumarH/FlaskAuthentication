from flask import Flask, render_template,url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, login_required,logout_user, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

'''
Now, I've configured database using sqlite. But, yet to create a table/model.
post creating model login to python shell and execute the below commands
python
db.create_all()
exit() 
sqlite3 database.db ( to login to the database)
'''

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signin"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Creating a Table - > User -> and columns -> id, username & password
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username =  db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username=StringField(validators={InputRequired(), Length(min=4, max=20)}, render_kw={"placeholder":"Username"})
    password=PasswordField(validators={InputRequired(), Length(min=4, max=20)}, render_kw={"placeholder":"Password"})
    submit=SubmitField('Register')
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username: 
            raise ValidationError("Username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username=StringField(validators={InputRequired(), Length(min=4, max=20)}, render_kw={"placeholder":"Username"})
    password=PasswordField(validators={InputRequired(), Length(min=4, max=20)}, render_kw={"placeholder":"Password"})
    submit=SubmitField('login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signin', methods=["GET", "POST"])
def signin():
    form=LoginForm()
    if form.validate_on_submit:
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('signin.html', form=form)

@app.route('/signup', methods=["GET", "POST"])
def signup():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('signin'))

    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/signout', methods=["GET", "POST"])
@login_required
def signout():
    logout_user()
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)