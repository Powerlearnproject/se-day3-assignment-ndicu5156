from flask import Blueprint, request, jsonify, Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, get_jwt_identity, 
    jwt_required, JWTManager
)
from datetime import datetime, timedelta
from email_validator import validate_email, EmailNotValidError
import random
import re
from models import *

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your-secret-key-here"  # Change this!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///social_app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

bcrypt = Bcrypt(app)
db.init_app(app)
jwt = JWTManager(app)
main_bp = Blueprint('main', __name__)

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    return True

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_to_email(email, otp):
    # Implement email sending logic here
    pass

# Authentication Routes
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        required_fields = ['username', 'email', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400



        # Validate password
        if not validate_password(data['password']):
            return jsonify({
                "error": "Password must be at least 8 characters long and contain uppercase letter and number"
            }), 400

        # Check username length and characters
        if not re.match("^[a-zA-Z0-9_]{3,20}$", data['username']):
            return jsonify({
                "error": "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
            }), 400

        existing_user = User.query.filter(
            (User.email == data['email']) | (User.username == data['username'])
        ).first()
        
        if existing_user:
            return jsonify({
                "error": "Email or username already exists"
            }), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            username=data['username'],
            email=data['email'],
            password_hash=hashed_password
        )
        
        user.save()
        access_token = create_access_token(identity=user.id)
        
        return jsonify({
            "message": "User created successfully",
            "access_token": access_token,
            "user": user.to_dict()
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not all(k in data for k in ['email', 'password']):
            return jsonify({"error": "Missing email or password"}), 400

        user = User.query.filter_by(email=data["email"]).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, data["password"]):
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            access_token = create_access_token(identity=user.id)
            return jsonify({
                "access_token": access_token,
                "user": user.to_dict()
            }), 200
            
        return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Routes
@main_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    try:
        user = User.query.get_or_404(user_id)
        return jsonify(user.to_dict(include_email=False))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user_profile(user_id):
    try:
        current_user_id = get_jwt_identity()
        if current_user_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        if 'username' in data:
            if not re.match("^[a-zA-Z0-9_]{3,20}$", data['username']):
                return jsonify({"error": "Invalid username format"}), 400
            existing_user = User.query.filter_by(username=data['username']).first()
            if existing_user and existing_user.id != user_id:
                return jsonify({"error": "Username already taken"}), 400
            user.username = data['username']
            
        if 'bio' in data:
            if len(data['bio']) > 500:
                return jsonify({"error": "Bio too long"}), 400
            user.bio = data['bio']
            
        if 'avatar_url' in data:
            user.avatar_url = data['avatar_url']
            
        db.session.commit()
        return jsonify(user.to_dict())

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Post Routes
@main_bp.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if 'content' not in data or not data['content'].strip():
            return jsonify({"error": "Content is required"}), 400
            
        if len(data['content']) > 5000:
            return jsonify({"error": "Content too long"}), 400
            
        post = Post(
            content=data['content'],
            user_id=current_user_id,
            media_url=data.get('media_url')
        )
        
        post.save()
        return jsonify(post.to_dict()), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/posts/<int:post_id>', methods=['GET'])
@jwt_required()
def get_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        return jsonify(post.to_dict(include_comments=True))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/posts/<int:post_id>', methods=['PUT'])
@jwt_required()
def update_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)
        
        if post.user_id != current_user_id:
            return jsonify({"error": "Unauthorized"}), 403
            
        data = request.get_json()
        if 'content' in data:
            if not data['content'].strip():
                return jsonify({"error": "Content cannot be empty"}), 400
            if len(data['content']) > 5000:
                return jsonify({"error": "Content too long"}), 400
            post.content = data['content']
            
        db.session.commit()
        return jsonify(post.to_dict())

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Comment Routes
@main_bp.route('/posts/<int:post_id>/comments', methods=['POST'])
@jwt_required()
def create_comment(post_id):
    try:
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)
        data = request.get_json()
        
        if 'content' not in data or not data['content'].strip():
            return jsonify({"error": "Content is required"}), 400
            
        if len(data['content']) > 1000:
            return jsonify({"error": "Content too long"}), 400
            
        comment = Comment(
            content=data['content'],
            user_id=current_user_id,
            post_id=post_id
        )
        
        comment.save()
        return jsonify(comment.to_dict()), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route('/comments/<int:comment_id>', methods=['PUT', 'DELETE'])
@jwt_required()
def manage_comment(comment_id):
    try:
        current_user_id = get_jwt_identity()
        comment = Comment.query.get_or_404(comment_id)
        
        if comment.user_id != current_user_id:
            return jsonify({"error": "Unauthorized"}), 403
            
        if request.method == 'DELETE':
            comment.delete()
            return jsonify({"message": "Comment deleted successfully"})
            
        data = request.get_json()
        if 'content' in data:
            if not data['content'].strip():
                return jsonify({"error": "Content cannot be empty"}), 400
            if len(data['content']) > 1000:
                return jsonify({"error": "Content too long"}), 400
            comment.content = data['content']
            
        db.session.commit()
        return jsonify(comment.to_dict())

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Like Routes
@main_bp.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def toggle_like(post_id):
    try:
        current_user_id = get_jwt_identity()
        post = Post.query.get_or_404(post_id)
        
        like = Like.query.filter_by(
            user_id=current_user_id,
            post_id=post_id
        ).first()
        
        if like:
            db.session.delete(like)
            action = 'unliked'
        else:
            like = Like(user_id=current_user_id, post_id=post_id)
            db.session.add(like)
            action = 'liked'
        
        db.session.commit()
        return jsonify({
            "message": f"Post {action} successfully",
            "likes_count": post.like_count
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

app.register_blueprint(main_bp, url_prefix='/api')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)