from app import app, db

def clear_database():
    with app.app_context():
        db.drop_all()
        print("All tables dropped.")

if __name__ == "__main__":
    clear_database()
