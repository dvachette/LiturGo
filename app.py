#-*- coding: utf-8 -*-

# Created by : Donatien VACHETTE

# Date : 10/06/2021

# Description : This file is the main file of the project. It contains the main code of the project.

# Importing the necessary libraries

# Flask is used to manage web pages
from flask import Flask, request, session, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
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


# Creating the Flask app
app = Flask(__name__)

# Setting the secret key and the database URI
app.secret_key = "MyOwnSuperSecretKeyThatNoOneElseShouldKnow"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Creating the database
db = SQLAlchemy(app)

# Logging configuration
logging.basicConfig(level=logging.DEBUG)


# ==== Classes ==== #

# Page list class
@dataclass
class pages:
    pass

# "Paroisse" class
class Paroisse(db.model):
    """
    Paroisse class

    Attributes:
    id : int : the id of the paroisse
    name : str : the name of the paroisse
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f"<Paroisse {self.name}>"

# "Intervenant" class
class Intervenant(db.model):
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

    
    def __repr__(self):
        return f"<Intervenant {self.name}>"


# "Eglise" class
class Eglise(db.model):
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
    paroisse = db.relationship('Paroisse', backref=db.backref('eglises', lazy=True))
    
    def __repr__(self):
        return f"<Eglise {self.name}>"
    
# "Type" class
class Type(db.model):
    """
    Type class

    Attributes:
    id : int : the id of the type
    name : str : the name of the type
    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f"<Type {self.name}>"

# "Required" class
class Required(db.model):
    """
    Required class
    
    Attributes:
    id : int : the id of the required relation
    type : Type : the type of celebration
    role : Role : the role required
    level : int : the level of the required role : 0 is absent, 1 is optional and 2 is required
    """
    id = db.Column(db.Integer, primary_key=True)
    type = db.relationship('Type', backref=db.backref('required', lazy=True))
    role = db.relationship('Role', backref=db.backref('required', lazy=True))
    level = db.Column(db.Integer, nullable=False) 

    
    def __repr__(self):
        return f"<Required {self.name}>"
    
# "Role" class
class Role(db.model):
    """
    Role class

    Attributes:
    id : int : the id of the role
    name : str : the name of the role
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    def __repr__(self):
        return f"<Role {self.name}>"

# "Celebration" class
class Celebration(db.model):
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
    eglise = db.relationship('Eglise', backref=db.backref('celebrations', lazy=True))
    type = db.relationship('Type', backref=db.backref('celebrations', lazy=True))
    intervenants = db.relationship('Intervenant', secondary='intervenant_celebration', backref=db.backref('celebrations', lazy=True))
    
    def __repr__(self):
        return f"<Celebration {self.date}>"
    
# "Intervenant_Celebration" class
class Intervenant_Celebration(db.model):
    """
    Intervenant_Celebration class

    Attributes:
    id : int : the id of the intervenant_celebration relation
    intervenant : Intervenant : the intervenant
    celebration : Celebration : the celebration
    """
    id = db.Column(db.Integer, primary_key=True)
    intervenant = db.relationship('Intervenant', backref=db.backref('intervenant_celebrations', lazy=True))
    celebration = db.relationship('Celebration', backref=db.backref('intervenant_celebrations', lazy=True))

    
    def __repr__(self):
        return f"<Intervenant_Celebration {self.intervenant.id} {self.celebration.id}>"
    
# ==== Decorators ==== #

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('You need to be logged in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def group_required(groups : list):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('You need to be logged in to access this page', 'danger')
                return redirect(url_for('login'))
            if session['user'].group not in groups:
                flash('You do not have the right to access this page', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==== Routes ==== #
# Index route
# This route is the main route of the project. It displays the main page of the project.
# It is accessible by everyone.
# It displays the main page of the project.
@app.route('/')
def index():
    return render_template('index.html')
