from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import event

db = SQLAlchemy()
bcrypt = Bcrypt()

class BaseModel(db.Model):
    __abstract__ = True
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

class User(BaseModel):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    otp_code = db.Column(db.String(6), nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    bio = db.Column(db.String(500), nullable=True)
    avatar_url = db.Column(db.String(255), nullable=True)
    
    # Relationships
    posts = relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    comments = relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    @hybrid_property
    def post_count(self):
        return self.posts.count()

    @hybrid_property
    def follower_count(self):
        return self.followers.count()

    def set_password(self, password):
        if not password or len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_email=False):
        data = {
            'id': self.id,
            'username': self.username,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'post_count': self.post_count,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'created_at': self.created_at.isoformat()
        }
        if include_email:
            data['email'] = self.email
        return data

    def __repr__(self):
        return f'<User {self.username}>'

class Post(BaseModel):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    is_edited = db.Column(db.Boolean, default=False, nullable=False)
    media_url = db.Column(db.String(255), nullable=True)
    
    comments = relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    likes = relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')

    @hybrid_property
    def like_count(self):
        return self.likes.count()

    @hybrid_property
    def comment_count(self):
        return self.comments.count()

    def to_dict(self, include_comments=False):
        data = {
            'id': self.id,
            'content': self.content,
            'author': self.author.to_dict(),
            'created_at': self.created_at.isoformat(),
            'is_edited': self.is_edited,
            'media_url': self.media_url,
            'like_count': self.like_count,
            'comment_count': self.comment_count
        }
        if include_comments:
            data['comments'] = [comment.to_dict() for comment in self.comments]
        return data

    def __repr__(self):
        return f'<Post {self.id} by {self.author.username}>'

class Comment(BaseModel):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), nullable=False)
    is_edited = db.Column(db.Boolean, default=False, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'author': self.author.to_dict(),
            'created_at': self.created_at.isoformat(),
            'is_edited': self.is_edited
        }

    def __repr__(self):
        return f'<Comment {self.id} by {self.author.username}>'

class Like(BaseModel):
    __tablename__ = 'likes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id', ondelete='CASCADE'), nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),
        db.Index('idx_user_post_like', 'user_id', 'post_id')
    )

    def __repr__(self):
        return f'<Like {self.id} by {self.user.username} on post {self.post_id}>'

@event.listens_for(Post.content, 'set')
def post_edit_listener(target, value, oldvalue, initiator):
    if getattr(target, 'id', None) is not None and value != oldvalue:
        target.is_edited = True

@event.listens_for(Comment.content, 'set')
def comment_edit_listener(target, value, oldvalue, initiator):
    if getattr(target, 'id', None) is not None and value != oldvalue:
        target.is_edited = True