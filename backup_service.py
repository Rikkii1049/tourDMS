import os
import subprocess
from datetime import datetime
import boto3

# Use environment variables from Railway environment settings
AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
S3_BUCKET_NAME = os.environ["S3_BUCKET_NAME"]
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME = os.environ["DB_NAME"]

def backup_and_upload():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"/tmp/db_backup_{timestamp}.sql"
    
    dump_cmd = [
        "mysqldump",
        "-u", DB_USER,
        f"-p{DB_PASSWORD}",
        DB_NAME
    ]
    with open(backup_file, "w") as out_file:
        subprocess.run(dump_cmd, stdout=out_file, check=True)

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    s3_key = f"db_backups/{os.path.basename(backup_file)}"
    s3.upload_file(backup_file, S3_BUCKET_NAME, s3_key)

    print(f"[OK] Uploaded to s3://{S3_BUCKET_NAME}/{s3_key}")
    os.remove(backup_file)

if __name__ == "__main__":
    backup_and_upload()
