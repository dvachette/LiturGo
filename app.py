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

app = Flask(__name__)
app.secret_key = "MyOwnSuperSecretKeyThatNoOneElseShouldKnow"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

logging.basicConfig(level=logging.DEBUG)
