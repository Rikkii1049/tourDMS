import os
import subprocess
from datetime import datetime
import boto3
from dotenv import load_dotenv

load_dotenv()

def dump_database():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"/tmp/db_backup_{timestamp}.sql"
    
    # Run mysqldump (you can adapt this for pg_dump)
    dump_cmd = [
        "mysqldump",
        "-u", os.getenv("DB_USER"),
        f"-p{os.getenv('DB_PASSWORD')}",
        os.getenv("DB_NAME")
    ]

    with open(backup_file, "w") as out_file:
        subprocess.run(dump_cmd, stdout=out_file, check=True)
    
    return backup_file

def upload_to_s3(file_path):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
    
    bucket = os.getenv("S3_BUCKET_NAME")
    s3_key = f"db_backups/{os.path.basename(file_path)}"
    
    s3.upload_file(file_path, bucket, s3_key)
    
    print(f"Uploaded {file_path} to s3://{bucket}/{s3_key}")
    os.remove(file_path)

def backup_and_upload():
    try:
        file_path = dump_database()
        upload_to_s3(file_path)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Dump failed: {e}")
    except Exception as e:
        print(f"[ERROR] Backup error: {e}")
