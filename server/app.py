#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json_data = request.get_json()
        
        try:
            username = json_data.get('username')
            password = json_data.get('password')
            
            if not username:
                return {'errors': 'Username is required'}, 422
            
            new_user = User(
                username=username,
                image_url=json_data.get('image_url'),
                bio=json_data.get('bio'),
            )
            new_user.password_hash = password
            
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            
            return new_user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {'errors': 'Username already exists'}, 422
        except Exception as e:
            db.session.rollback()
            return {'errors': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'errors': 'No active session'}, 401
        
        user = User.query.get(user_id)
        
        if not user:
            return {'errors': 'User not found'}, 401
        
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        json_data = request.get_json()
        
        username = json_data.get('username')
        password = json_data.get('password')
        
        user = User.query.filter(User.username == username).first()
        
        if not user or not user.authenticate(password):
            return {'errors': 'Invalid username or password'}, 401
        
        session['user_id'] = user.id
        
        return user.to_dict(), 200

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'errors': 'No active session'}, 401
        
        session.clear()
        
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'errors': 'No active session'}, 401
        
        user = User.query.get(user_id)
        
        if not user:
            return {'errors': 'User not found'}, 401
        
        recipes = user.recipes
        
        return [recipe.to_dict() for recipe in recipes], 200
    
    def post(self):
        user_id = session.get('user_id')
        
        if not user_id:
            return {'errors': 'No active session'}, 401
        
        json_data = request.get_json()
        
        try:
            title = json_data.get('title')
            instructions = json_data.get('instructions')
            minutes_to_complete = json_data.get('minutes_to_complete')
            
            if not title:
                return {'errors': 'Title is required'}, 422
            
            if not instructions or len(instructions) < 50:
                return {'errors': 'Instructions must be at least 50 characters'}, 422
            
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id,
            )
            
            db.session.add(new_recipe)
            db.session.commit()
            
            return new_recipe.to_dict(), 201
        except IntegrityError as e:
            db.session.rollback()
            return {'errors': str(e)}, 422
        except ValueError as e:
            db.session.rollback()
            return {'errors': str(e)}, 422
        except Exception as e:
            db.session.rollback()
            return {'errors': str(e)}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)