from flask import Flask
from config import Config
from .extensions import db, migrate, jwt, mail, cors, bcrypt
from flask_cors import CORS

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)
    cors.init_app(app)
    bcrypt.init_app(app)

    # Register blueprints
    from .routes import auth_bp
    from .routes import users_bp
    from .routes  import posts_bp
    from .routes  import messages_bp
    from .routes import groups_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(posts_bp, url_prefix='/api/posts')

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)