import os
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash


app = create_app()

with app.app_context():
    db.create_all()
    
    #CREATE admin account if it doesnt exist
    existing = User.query.filter_by(username='admin').first()
    if not existing:
        admin = User(
            username = 'admin',
            email = 'admin@pci.com',
            password = generate_password_hash('admin123'),
            role = 'admin'
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin account created")
        print("username: admin")
        print("password: admin123")
    else:
        print("DATABASE READY")
        
        
    
  
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
        
