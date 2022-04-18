from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re 
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


# dont mess up indentation here or shit wont work
class User:
    db = "registration"
    def __init__(self,data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.confirm_password = data['confirm_password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def save(cls,data):
        query = "INSERT into users (first_name, last_name, email, password) VALUES (%(first_name)s,%(last_name)s,%(email)s,%(password)s);"
        return connectToMySQL(cls.db).query_db(query,data)

    @classmethod
    def get_by_id(cls,data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        results = connectToMySQL(cls.db).query_db(query,data)
        if results: 
            return cls(results[0])  

    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(cls.db).query_db(query,data)
        # Didn't find a matching user
        if len(result) < 1:
            return False
        return cls(result[0])

    @staticmethod
    def is_valid_registration(user):
        is_valid = True
        if len(user['first_name']) < 3:
            is_valid = False
            flash("First Name must be atleast 3 characters.", "registration")
        if len(user['last_name']) < 3:
            is_valid = False
            flash("Last Name must be atleast 3 characters.", 'registration')
        if len(user['password']) < 8:
            is_valid = False
            flash("Password must be at least 8 characters long.", 'registration')
        elif user['password'] != user['confirm_password']:
            is_valid = False
            flash('Passwords do not match', 'registration')
        query = "SELECT * FROM users WHERE email = %(email)s;"
        results = connectToMySQL(User.db).query_db(query, user)
        if results: 
            flash("Email address is already in use.", 'registration')
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("Invalid Email address", 'registration')
            is_valid = False
        return is_valid

    @staticmethod
    def is_valid_login(user):
        is_valid = True
        if len(user['email']) < 1:
            is_valid = False
            flash('Email is required', 'login')
        if len(user['password']) < 1:
            is_valid = False
            flash('Password is required', 'login')
        return is_valid


