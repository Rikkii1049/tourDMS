import os
from app import app, db, TblUser
from werkzeug.security import generate_password_hash

def truncate_all_tables():
    meta = db.metadata
    with app.app_context():
        conn = db.engine.connect()
        trans = conn.begin()
        print("Truncating all tables...")
        conn.execute("SET session_replication_role = 'replica';")
        for table in reversed(meta.sorted_tables):
            conn.execute(table.delete())  # Use DELETE for SQLAlchemy compatibility
        conn.execute("SET session_replication_role = 'origin';")
        trans.commit()
        print("All tables truncated.")

def create_master_user():
    with app.app_context():
        existing_user = TblUser.query.filter_by(nama='admin').first()
        if not existing_user:
            print("Creating master user...")
            user = TblUser(
                nama='admin',
                password=generate_password_hash('passwordadminbaru123'),  # Change this
                role='admin',
                email='DMSadminemail@gmail.com',
                status='active'
            )
            db.session.add(user)
            db.session.commit()
            print("Master user created.")
        else:
            print("Master user already exists.")

if __name__ == '__main__':
    if os.environ.get("ALLOW_DB_RESET") != "true":
        print("Unauthorized: Set ALLOW_DB_RESET=true in environment variables to run this script.")
        exit(1)

    with app.app_context():
        db.create_all()
        truncate_all_tables()
        create_master_user()