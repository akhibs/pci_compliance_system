import os
from app import create_app, db


app = create_app()

with app.app_context():
    #Create all databasetable
    db.create_all()
    print("database ready")
    
  
        
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
        
