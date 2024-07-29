# -*- coding: utf-8 -*-

# Created by : Donatien VACHETTE

# Description : This file is the main file of the project.
# It contains the main code of the project.

# Importing the necessary libraries

# Flask is used to manage web pages
import logging.config
from flask import (
    Flask,
    request,
    session,
    redirect,
    url_for,
    render_template,
    flash,
    abort,
)
from flask_sqlalchemy import SQLAlchemy

# Werkzeug is used to manage passwords and security
from werkzeug.security import generate_password_hash, check_password_hash

# Dataclass is used to create classes with attributes that can be used as a dictionary
from dataclasses import dataclass

# Datetime is used to manage dates
from datetime import datetime

# Wraps is used to create decorators
from functools import wraps

# OS is used to manage the operating system
import os

# Subprocess is used to run shell commands
import subprocess

# Logging is used to log messages
import logging

# ==== Constants ==== #
DEBUG = True

# Creating the Flask app
app = Flask(__name__)

# Setting the secret key and the database URI
app.secret_key = 'MyOwnSuperSecretKeyThatNoOneElseShouldKnow'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Creating the database
db = SQLAlchemy(app)

# Logging configuration
logging.basicConfig(level=logging.DEBUG)
file_loging = logging.FileHandler('app.log')
file_loging.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
file_loging.setFormatter(formatter)
app.logger.addHandler(file_loging)

# ==== Classes ==== #

# ---- Dataclasses ---- #
# Page list class
@dataclass
class Templates:
    """
    Templates class

    Template().page: str : the html code of the page
    """

    index: str = 'index.html'


@dataclass
class AdminRoutes:
    """
    AdminRoutes class

    AdminRoutes().home: str : the route of the admin home page
    """

    home: str = 'admin_home'
    login: str = 'login'
    index: str = 'index'


@dataclass
class Routes:
    """
    Routes class

    Routes().index: str : the route of the index page
    Routes().login: str : the route of the login page
    """

    home: str = 'home'
    login: str = 'login'
    index: str = 'index'


# ---- Database classes ---- #

# "Paroisse" class
class Paroisse(db.Model):
    """
    Paroisse class

    Attributes:
    id : int : the id of the paroisse
    name : str : the name of the paroisse
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Paroisse {self.name}>'


# "Intervenant" class
class Intervenant(db.Model):
    """
    Intervenant class

    Attributes:
    id : int : the id of the intervenant
    name : str : the name of the intervenant
    firstname : str : the firstname of the intervenant
    email : str : the email of the intervenant
    password : str : the password of the intervenant
    phone : str : the phone of the intervenant
    desc : str : the description of the intervenant
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    desc = db.Column(db.String(100), nullable=False)

    def is_role(self, group: str | list[str]) -> bool:
        if isinstance(group, str):
            _group = Role.query.filter_by(name=group).first()
            group_id = _group.id
            roles = Intervenant_Role.query.filter_by(
                intervenant_id=self.id
            ).all()
            for role in roles:
                if role.role_id == group_id:
                    return True
            return False
        elif isinstance(group, list):
            group_id = []
            for g in group:
                _group = Role.query.filter_by(name=g).first()
                group_id.append(_group.id)
            roles = Intervenant_Role.query.filter_by(
                intervenant_id=self.id
            ).all()
            for role in roles:
                if role.role_id in group_id:
                    return True
            return False

    def __repr__(self):
        return f'<Intervenant {self.name}>'


# "Eglise" class
class Eglise(db.Model):
    """
    Eglise class

    Attributes:
    id : int : the id of the eglise
    name : str : the name of the eglise
    address : str : the address of the eglise
    paroisse_id : int : the id of the paroisse of the eglise
    paroisse : Paroisse : the paroisse of the eglise
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    paroisse_id = db.Column(
        db.Integer, db.ForeignKey('paroisse.id'), nullable=False
    )
    paroisse = db.relationship(
        'Paroisse', backref=db.backref('eglises', lazy=True)
    )

    def __repr__(self):
        return f'<Eglise {self.name}>'


# "Type" class
class Type(db.Model):
    """
    Type class

    Attributes:
    id : int : the id of the type
    name : str : the name of the type
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Type {self.name}>'


# "Required" class
class Required(db.Model):
    """
    Required class

    Attributes:
    id : int : the id of the required relation
    type : Type : the type of celebration
    role : Role : the role required
    level : int : the level of the required role : 0 is absent, 1 is optional and 2 is required
    """

    id = db.Column(db.Integer, primary_key=True)
    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = db.relationship('Type', backref=db.backref('required', lazy=True))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref=db.backref('required', lazy=True))
    level = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Required {self.name}>'


# "Role" class
class Role(db.Model):
    """
    Role class

    Attributes:
    id : int : the id of the role
    name : str : the name of the role
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Role {self.name}>'


# "Celebration" class
class Celebration(db.Model):
    """
    Celebration class

    Attributes:
    id : int : the id of the celebration
    date : datetime : the date of the celebration
    eglise : Eglise : the eglise of the celebration
    type : Type : the type of the celebration
    """

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    eglise_id = db.Column(
        db.Integer, db.ForeignKey('eglise.id'), nullable=False
    )
    eglise = db.relationship(
        'Eglise', backref=db.backref('celebrations', lazy=True)
    )
    type_id = db.Column(db.Integer, db.ForeignKey('type.id'), nullable=False)
    type = db.relationship(
        'Type', backref=db.backref('celebrations', lazy=True)
    )

    def __repr__(self):
        return f'<Celebration {self.date}>'


# "Intervenant_Celebration" class
class Intervenant_Celebration(db.Model):
    """
    Intervenant_Celebration class

    Attributes:
    id : int : the id of the intervenant_celebration relation
    intervenant : Intervenant : the intervenant
    celebration : Celebration : the celebration
    """

    id = db.Column(db.Integer, primary_key=True)
    id_intervenant = db.Column(
        db.Integer, db.ForeignKey('intervenant.id'), nullable=False
    )
    intervenant = db.relationship(
        'Intervenant',
        backref=db.backref('intervenant_celebrations', lazy=True),
    )
    id_celebration = db.Column(
        db.Integer, db.ForeignKey('celebration.id'), nullable=False
    )
    celebration = db.relationship(
        'Celebration',
        backref=db.backref('intervenant_celebrations', lazy=True),
    )

    def __repr__(self):
        return f'<Intervenant_Celebration {self.intervenant.id} {self.celebration.id}>'


class Intervenant_Role(db.Model):
    """
    Intervenant_Role class

    Attributes:
    id : int : the id of the intervenant_role relation
    intervenant : Intervenant : the intervenant
    role : Role : the role
    """

    id = db.Column(db.Integer, primary_key=True)
    intervenant_id = db.Column(
        db.Integer, db.ForeignKey('intervenant.id'), nullable=False
    )
    intervenant = db.relationship(
        'Intervenant', backref=db.backref('Intervenant_roles', lazy=True)
    )
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship(
        'Role', backref=db.backref('Intervenant_roles', lazy=True)
    )

    def __repr__(self):
        return f'<Intervenant_Role {self.intervenant.id} {self.role.id}>'


# ==== Decorators ==== #


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            flash('You need to be logged in to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            session['next'] = request.url
            flash('You need to be logged in to access this page', 'danger')
            return redirect(url_for('index'))
        if (
            not Intervenant.query.filter(Intervenant.id == session['user_id'])
            .first()
            .is_role('admin')
        ):
            flash('You do not have the right to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# ==== Functions ==== #
def page(route: str, user: Intervenant):
    """
    htmlpage function

    This function is used to return the html code of a page.

    Parameters:
    path : str : the path of the page
    user : Intervenant : the user who is requesting the page
    """
    if user.is_role('admin'):
        template = AdminRoutes()
    else:
        template = Routes()
    return getattr(template, route)


# ==== Routes ==== #
# Index route
# This route is the main route of the project.
# It displays the main page of the project.
# It is accessible by everyone.
@app.route('/')
def index():
    return render_template('index.html')


# Login route
# This route is used to login the user.
# It is accessible by everyone.
# It displays the login page.
@app.route('/login', methods=['POST'])
def login():
    print('LOGIN EN COUR')
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Intervenant.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                app.logger.info(f'user {user.id} logged in')
                return redirect(url_for(page('home', user)))
            else:
                app.logger.warning(
                    f'user {user.id} tried to log in with a wrong password'
                )
                flash('Invalid password', 'danger')
                return redirect(url_for('index'))
        else:
            app.logger.warning(f"user with email '{email}' not found")
            flash('User not found', 'danger')
            return redirect(url_for('index'))


# admin home route
# This route is used to display the admin home page.
# It is accessible by the admin.
@app.route('/admin')
@login_required
def admin_home():
    return render_template('home-admin.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=DEBUG)
