from extensions import db

class Admin(db.Model):
    __tablename__ = 'admin_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    is_default = db.Column(db.Boolean, default=False)

    def to_dict(self):
        """Convert admin object to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'is_default': self.is_default
        }

    def __repr__(self):
        return f'<Admin {self.id}>'