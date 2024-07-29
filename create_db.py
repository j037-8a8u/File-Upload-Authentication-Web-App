from app import app, db

def create_database():
    with app.app_context():
        db.create_all()
        print("Database schema created.")

if __name__ == "__main__":
    create_database()
