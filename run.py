import os
from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    #Create all databasetable
    db.create_all()
    
    #create a default admin user if none exists
    existing = User.query.filter_by(username='admin').first()
    if not existing:
        admin = User(
            username = 'admin',
            password = generate_password_hash('admin123'),
            role = 'admin'
        )
        db.session.add(admin)
        db.session.commit()
        print(" Default admin user created ")
        print("  Username: admin")
        print("  password:admin123")
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
        
