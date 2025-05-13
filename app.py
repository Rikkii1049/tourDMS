import pytz, os, mimetypes, re, boto3, atexit
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import case, func
from flask_login import login_user, UserMixin, login_required, LoginManager, current_user, logout_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from botocore.client import Config
from dotenv import load_dotenv
from apscheduler.schedulers.blocking import BlockingScheduler
from backup_service import backup_and_upload

app = Flask(__name__)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

s3_client = boto3.client(
    's3',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_REGION'),
    config=Config(s3={'addressing_style': 'virtual'}),
    endpoint_url='https://s3.ap-southeast-3.amazonaws.com'
)

BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

# file upload configs
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # or use a safer directory
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {'docx', 'doc', 'pdf', 'xls', 'xlsx', 'jpg', 'img'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)  # attach to your app
login_manager.login_view = 'login'  # name of your login view function

# Optional: message shown when redirecting to login
login_manager.login_message = "You must be logged in to access this page."

db = SQLAlchemy(app)

# DB backup
scheduler = BlockingScheduler()
scheduler.add_job(backup_and_upload, trigger='interval', days=1)

print("Backup service started. Running every 24 hours.")
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# Get WIB time
def get_wib_time():
    wib = pytz.timezone('Asia/Jakarta')
    now = datetime.now(wib)
    return now.replace(microsecond=0)

class TblBidang(db.Model):
    __tablename__ = 'tbl_bidang'

    id_bidang = db.Column(db.Integer, primary_key=True)
    nama_bidang = db.Column(db.Text, nullable=False)
    keterangan = db.Column(db.Text)
    status = db.Column(db.Text)

    users = db.relationship('TblUser', backref='bidang', lazy=True)
    dokumen = db.relationship('TblDokumen', backref='bidang_upload_ref', lazy=True)

class TblUser(db.Model, UserMixin):
    __tablename__ = 'tbl_user'

    id_user = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text)
    password = db.Column(db.Text, nullable=False)
    web_role = db.Column(db.Text, nullable=False)
    id_bidang = db.Column(db.Integer, db.ForeignKey('tbl_bidang.id_bidang'), nullable=False)
    dibuat_pada = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.Text, nullable=False)
    jabatan = db.Column(db.Text, nullable=False)

    dokumen = db.relationship('TblDokumen', backref='uploader_ref', lazy=True)
    versi_dokumen = db.relationship('TblVersiDokumen', backref='uploader_ref', lazy=True)
    logs = db.relationship('TblLogs', backref='user_ref', lazy=True)
    
    def get_id(self):
        return str(self.id_user)

class TblDokumen(db.Model):
    __tablename__ = 'tbl_dokumen'

    id_dokumen = db.Column(db.Integer, primary_key=True)
    judul_dokumen = db.Column(db.Text)
    nama_file = db.Column(db.Text)
    uploader = db.Column(db.Integer, db.ForeignKey('tbl_user.id_user'), nullable=False)
    bidang_upload = db.Column(db.Integer, db.ForeignKey('tbl_bidang.id_bidang'), nullable=False)
    tanggal_upload = db.Column(db.DateTime, nullable=False)
    deskripsi = db.Column(db.Text)
    url_file = db.Column(db.Text)
    versi = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Text, nullable=False)
    doc_code = db.Column(db.Text, nullable=False)
    id_kategori = db.Column(db.Text, db.ForeignKey('tbl_kategori_dokumen.id_kategori'))

    versi_dokumen = db.relationship('TblVersiDokumen', backref='dokumen', lazy=True)
    logs = db.relationship('TblLogs', backref='dokumen', lazy=True)
    tags = db.relationship('TblTags', backref='tags', lazy=True)
    kategori = db.relationship('TblKategoriDokumen', backref='dokumen')

class TblVersiDokumen(db.Model):
    __tablename__ = 'tbl_versi_dokumen'

    id_versi_dokumen = db.Column(db.Integer, primary_key=True)
    id_dokumen = db.Column(db.Integer, db.ForeignKey('tbl_dokumen.id_dokumen'), nullable=False)
    versi = db.Column(db.Integer, nullable=False)
    url_file = db.Column(db.Text)
    uploader = db.Column(db.Integer, db.ForeignKey('tbl_user.id_user'), nullable=False)
    diupload_pada = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Text)

class TblKategoriDokumen(db.Model):
    __tablename__ = 'tbl_kategori_dokumen'

    id_kategori = db.Column(db.Integer, primary_key=True)
    nama_kategori = db.Column(db.Text, nullable=False)
    keterangan = db.Column(db.Text)
    status = db.Column(db.Text)


class TblLogs(db.Model):
    __tablename__ = 'tbl_logs'

    id_log = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_user.id_user'), nullable=False)
    action = db.Column(db.Text, nullable=False)
    id_dokumen = db.Column(db.Integer, db.ForeignKey('tbl_dokumen.id_dokumen'), nullable=False)
    message = db.Column(db.Text)
    waktu = db.Column(db.DateTime, nullable=False)

class TblTags(db.Model):
    __tablename__ = 'tbl_tags'

    id = db.Column(db.Integer, primary_key=True)
    id_dokumen = db.Column(db.Integer, db.ForeignKey('tbl_dokumen.id_dokumen'), nullable=False)
    tag_name = db.Column(db.Text, nullable=False)

# generate doc_code
def generate_doc_code(prefix='DOC'):
    latest_code = (
        TblDokumen.query
        .filter(TblDokumen.doc_code.like(f'{prefix}%'))
        .order_by(TblDokumen.doc_code.desc())
        .first()
    )

    if latest_code:
        match = re.search(rf'{prefix}(\d+)', latest_code.doc_code)
        if match:
            number = int(match.group(1)) + 1
        else:
            number = 1
    else:
        number = 1

    return f"{prefix}{str(number).zfill(3)}"

@login_manager.user_loader
def load_user(user_id):
    return TblUser.query.get(int(user_id))

@app.route('/logout')
@login_required
def logout():
    save_log('User %s telah log out!' % current_user.nama, 'logout')
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    getdocs = db.session.query(TblDokumen) \
    .join(TblUser, TblDokumen.uploader == TblUser.id_user) \
    .join(TblBidang, TblDokumen.bidang_upload == TblBidang.id_bidang) \
    .join(TblKategoriDokumen, TblDokumen.id_kategori == TblKategoriDokumen.id_kategori) \
    .join(TblTags, TblDokumen.id_dokumen == TblTags.id_dokumen) \
    .filter(TblDokumen.status == 'active') \
    .group_by(TblDokumen.id_dokumen) \
    .order_by(TblDokumen.tanggal_upload.desc()) \
    .all()

    return render_template('index.html', docs=getdocs)

# Search func
@app.route('/search', methods=['POST'])
@login_required
def search():
    query = request.form['searchinput'].strip().lower()

    keyword_pattern = f"%{query}%"

    match_condition = (
        (TblDokumen.judul_dokumen.ilike(keyword_pattern)) |
        (TblUser.nama.ilike(keyword_pattern)) |
        (TblBidang.nama_bidang.ilike(keyword_pattern)) |
        (func.cast(TblDokumen.tanggal_upload, db.String).ilike(keyword_pattern)) |
        (TblKategoriDokumen.nama_kategori.ilike(keyword_pattern)) |
        (TblTags.tag_name.ilike(keyword_pattern))
    )

    results = db.session.query(TblDokumen).\
        join(TblUser, TblDokumen.uploader == TblUser.id_user).\
        join(TblBidang, TblDokumen.bidang_upload == TblBidang.id_bidang).\
        join(TblKategoriDokumen, TblDokumen.id_kategori == TblKategoriDokumen.id_kategori).\
        outerjoin(TblTags, TblDokumen.id_dokumen == TblTags.id_dokumen).\
        filter(TblDokumen.status == 'active').\
        options(
            db.joinedload(TblDokumen.uploader_ref),
            db.joinedload(TblDokumen.bidang_upload_ref),
            db.joinedload(TblDokumen.kategori)
        ).\
        order_by(
            case(
                (match_condition, 0),
                else_=1
            ),
            TblDokumen.tanggal_upload.desc()
        ).all()

    if results:
        return render_template('index.html', docs=results)
    else:
        flash('Dokumen dengan kata kunci/filter tidak ditemukan!', 'warning')
        return redirect(url_for('index'))



# ++++++++++++++ Start Sign in Block +++++++++++++++++++

@app.route('/adduser')
@login_required
def adduserpage():
    getallbidang = TblBidang.query.filter_by(status='active').all()
    getalluser = TblUser.query.options(db.joinedload(TblUser.bidang)).all()
    return render_template('add_user.html', users=getalluser, ambilBidang=getallbidang)

@app.route('/signinUserBaru', methods=['POST'])
@login_required
def signin():
    if request.method == 'POST':
        username = request.form['namaLogin']
        emailUser = request.form['emailLogin']
        passwordUser = request.form['passwordLogin']
        bidang = request.form['pilihBidang']
        role = request.form['pilihRole']
        jabatan = request.form['jabatanStaff']
        
        # Check if User Email exists
        userExistCheck = TblUser.query.filter_by(email=emailUser).first()
        if userExistCheck:
            save_log('User %s gagal di daftarkan!(Email duplikat)'% username,'signin')
            flash("Pengguna dengan Email ini sudah ada! Silahkan menggunakan Email lain")
            return redirect(url_for('adduserpage'))
        
        # Check if User name exists
        userExistCheck = TblUser.query.filter_by(nama=username).first()
        if userExistCheck:
            save_log('User %s gagal di daftarkan!(Nama duplikat)'% username,'signin')
            flash("Pengguna dengan Nama ini sudah ada! Silahkan menggunakan Email lain")
            return redirect(url_for('adduserpage'))
        
        timenow = get_wib_time()
        hashed_password = generate_password_hash(passwordUser)
        new_user = TblUser(nama=username, email=emailUser,password=hashed_password, web_role=role, id_bidang=bidang, dibuat_pada=timenow, jabatan=jabatan, status="Aktif")
        db.session.add(new_user)
        db.session.commit()
        
        save_log('User %s telah berhasil di daftarkan!'% username,'signin')
        flash("Pendaftaran sukses! silahkan login menggunakna Email dan Password.")
        return redirect(url_for('index'))
    
    flash("An error has occured!")
    return render_template('adduserpage.html')

# ++++++++++++++ End Sign in Block +++++++++++++++++++



# ++++++++++++++ Start Log in Block +++++++++++++++++++

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login_process():
    if request.method == 'POST':
        email = request.form.get('emailLogin')
        password = request.form.get('passwordLogin')

        user = TblUser.query.filter_by(email=email).first()
        if user:
            check_password = check_password_hash(user.password, password)
            if check_password:
                login_user(user)
                save_log('User %s telah berhasil login!'% current_user.nama,'login')
                flash('Login successful!', 'success')
                return redirect(url_for('index'))
            else:
                save_log('User %s telah gagal login!'% current_user.nama,'login')
                flash('Email atau password tidak valid!', 'danger')
                return render_template('login.html')
        else:
            save_log('User %s telah gagal login!'% current_user.nama,'login')
            flash('Email atau password tidak valid!', 'danger')
            return render_template('login.html')

# ++++++++++++++ End Log in Block +++++++++++++++++++



# ++++++++++++++ Start User Block +++++++++++++++++++

@app.route('/manageusers')
@login_required
def manageuserpage():
    getallbidang = TblBidang.query.all()
    getalluser = TblUser.query.options(db.joinedload(TblUser.bidang)).all()
    return render_template('manage_users.html', users=getalluser, ambilBidang=getallbidang)

@app.route('/edituserpage/<int:id>')
@login_required
def edituserpage(id):
    getuser = TblUser.query.get(id)
    idbidanguser = getuser.id_bidang
    bidang_user = TblBidang.query.get(idbidanguser)
    getallbidang = TblBidang.query.all()
    return render_template('edit_user.html', user=getuser, bidang_user=bidang_user, ambilBidang=getallbidang)

@app.route('/edituser<int:id>', methods=['POST'])
@login_required
def edituser(id):    
    if request.method == 'POST':
        getuser = TblUser.query.get_or_404(id)
        username = request.form['namaLogin']
        emailUser = request.form['emailLogin']
        
        name_before = getuser.nama
        
        # Check if username already exists
        check_username = TblUser.query.filter_by(nama=username).first()
        if check_username and getuser.id_user != id:
            save_log('User %s telah gagal mengedit data user %s!(Nama duplikat)'% current_user.nama % name_before,'misc_gagal')
            flash("Pengguna dengan Nama ini sudah ada! Silahkan menggunakan nama lain", 'danger')
            return redirect(url_for('edituserpage', id))
        
        # Check if Email already exists
        check_email = TblUser.query.filter_by(email=emailUser).first()
        if check_email and getuser.id_user != id:
            save_log('User %s telah gagal mengedit data user %s!(Email duplikat)'% current_user.nama % name_before,'misc_gagal')
            save_log('User %s telah mengedit data user %s!'% current_user.nama % name_before,'misc_gagal')
            flash("Pengguna dengan Email ini sudah ada! Silahkan menggunakan Email lain", 'danger')
            return redirect(url_for('edituserpage', id))
        
        getuser.nama = username
        getuser.email = emailUser
        getuser.id_bidang = request.form['pilihBidang']
        getuser.web_role = request.form['pilihRole']
        getuser.jabatan = request.form['jabatanStaff']
        db.session.commit()
        
        save_log('User %s telah mengedit data user %s!'% current_user.nama % name_before,'edit')
        flash('Data User/Staff %s berhasil diubah!' % username, 'success')
        return redirect(url_for('manageuserpage'))
    else:
        save_log('User %s gagal mengedit data user %s!'% current_user.nama % name_before,'misc_gagal')
        flash('Edit User/Staff gagal!', 'danger')
        return redirect(url_for('manageuserpage'))

@app.route('/deleteuser/', methods=['POST'])
@login_required
def deleteuser():
    if request.method == 'POST':
        id = request.form['user_id']
        find_user = TblUser.query.get(id)
        nama_user = find_user.nama
        if find_user:
            db.session.delete(find_user)
            db.session.commit()
            
            save_log('User %s berhasil hapus data user %s!'% current_user.nama % nama_user,'hapus')
            flash('User/Staff %s berhasil dihapus!' % nama_user, 'success')
            return redirect(url_for('manageuserpage'))
        else:
            save_log('User %s gagal hapus data user %s!'% current_user.nama % nama_user,'misc_gagal')
            flash('User/Staff %s gagal dihapus!' % nama_user, 'danger')
            return redirect(url_for('manageuserpage'))
    else:
        save_log('User %s gagal hapus data user %s!'% current_user.nama % nama_user,'misc_gagal')
        flash('User/Staff %s gagal dihapus!' % nama_user, 'danger')
        return redirect(url_for('manageuserpage'))

# ++++++++++++++ End User Block +++++++++++++++++++



# ++++++++++++++ Start Category Block +++++++++++++++++++
        
@app.route('/addcategory')
@login_required
def addcategorypage():
    return render_template('add_category.html')

@app.route('/addNewCategory', methods=['POST'])
@login_required
def addcategory():
    if request.method == 'POST':
        namakategori = request.form['namaKategori']
        deskripsikategori = request.form['deskripsiKategori']
        
        check_kategori = TblKategoriDokumen.query.filter_by(nama_kategori=namakategori).first()
        check_kategori_status = TblKategoriDokumen.query.filter_by(status='active').all()
        if check_kategori and check_kategori_status:
            save_log('User %s gagal menambahkan kategori!(Kategori duplikat)'% current_user.nama,'misc_gagal')
            flash('Kategori dengan nama ini sudah ada, silahkan gunakan nama lain!', 'danger')
            return redirect(url_for('managecategory'))
        
        new_category = TblKategoriDokumen(nama_kategori=namakategori, keterangan=deskripsikategori, status='active')
        db.session.add(new_category)
        db.session.commit()
        
        save_log('User %s berhasil menambahkan kategori baru!'% current_user.nama,'tambah')
        flash("Berhasil Menambahkan Kategori Baru!", "danger")
        return redirect(url_for('managecategory'))
    else:
        save_log('User %s gagal menambahkan kategori!(Error)!'% current_user.nama,'misc_gagal')
        flash("Gagal Menambahkan Kategori Baru!", "danger")
        return redirect(url_for('managecategory'))

@app.route('/editcategorypage<int:id>')
@login_required
def editcategorypage(id):
    getcategory = TblKategoriDokumen.query.get(id)
    return render_template('edit_category.html', category=getcategory)

@app.route('/editcategory<int:id>', methods=['POST'])
@login_required
def editcategory(id):
    if request.method == 'POST':
        get_category = TblKategoriDokumen.query.get_or_404(id)
        categoryName = request.form['namaCategory']
        
        check_kategori = TblKategoriDokumen.query.filter_by(nama_kategori=categoryName).first()
        check_kategori_status = TblKategoriDokumen.query.filter_by(status='active').all()
        if check_kategori and check_kategori_status:
            save_log('User %s gagal mengedit kategori!(Kategori Duplikat)'% current_user.nama,'misc_gagal')
            flash('Kategori dengan nama ini sudah ada, silahkan gunakan nama lain!')
            return redirect(url_for('editcategorypage'))
        
        get_category.nama_kategori = categoryName
        get_category.keterangan = request.form['keteranganCategory']
        db.session.commit()
        
        save_log('User %s berhasil mengedit kategori!'% current_user.nama,'edit')
        flash('Ketegori Dokumen %s berhasil diedit!' % categoryName, 'success')
        return redirect(url_for('managecategory'))
    else:
        save_log('User %s gagal mengedit kategori!(Error)'% current_user.nama,'misc_gagal')
        flash('Gagal edit data Kategori!', 'danger')
        return redirect(url_for('managecategory'))
        
@app.route('/managecategory')
@login_required
def managecategory():
    getallcategories = TblKategoriDokumen.query.filter_by(status='active').all()
    return render_template('manage_categories.html', categories=getallcategories)
    
@app.route('/deletecategory', methods=['POST'])
@login_required
def deletecategory():
    id = request.form['categoryId']
    if request.method == 'POST':
        inactive = 'inactive'
        get_category = TblKategoriDokumen.query.get_or_404(id)
        categoryname = get_category.nama_kategori
        get_category.status = inactive
        db.session.commit()
        
        save_log('User %s berhasil menghapus kategori!'% current_user.nama,'hapus')
        flash('Kategori dokumen %s berhasil dihapus!' % categoryname, 'success')
        return redirect(url_for('managecategory'))
    else:
        save_log('User %s gagal menghapus kategori!(Error)'% current_user.nama,'misc_gagal')
        flash('Kategori dokumen gagal dihapus!', 'danger')
        return redirect(url_for('managecategory'))
    
# ++++++++++++++ End Category Block +++++++++++++++++++



# ++++++++++++++ Start Bidang Block +++++++++++++++++++

@app.route('/addbidang')
@login_required
def addbidangpage():
    return render_template('add_bidang.html')

@app.route('/addNewBidang', methods=['POST'])
@login_required
def addbidang():
    if request.method == 'POST':
        namabidang = request.form['namaBidang']
        deskripsibidang = request.form['deskripsiBidang']
        
        check_bidang = TblBidang.query.filter_by(nama_bidang=namabidang).first()
        check_bidang_status = TblBidang.query.filter_by(status='active').all()
        if check_bidang and check_bidang_status:
            save_log('User %s gagal menambahkan bidang!(Nama Duplikat)'% current_user.nama,'misc_gagal')
            flash('Bidang dengan nama (%s) sudah ada, silahkan gunakan nama lain!' % namabidang, 'danger')
            return redirect(url_for('managebidang'))
        
        new_bidang = TblBidang(nama_bidang=namabidang, keterangan=deskripsibidang, status='active')
        db.session.add(new_bidang)
        db.session.commit()
        
        save_log('User %s berhasil menambahkan bidang!'% current_user.nama,'tambah')
        flash("Berhasil Menambahkan Bidang Baru (%s)!" % namabidang, 'success')
        return redirect(url_for('managebidang'))
    save_log('User %s gagal menambahkan bidang!'% current_user.nama,'misc_gagal')
    flash("An Error Has Occured!", "danger")
    return render_template('manage_bidang.html')

@app.route('/editbidangpage<int:id>')
@login_required
def editbidangpage(id):
    getbidang = TblBidang.query.get(id)
    return render_template('edit_bidang.html', bidang=getbidang)

@app.route('/editbidang<int:id>', methods=['POST'])
@login_required
def editbidang(id):
    if request.method == 'POST':
        get_bidang = TblBidang.query.get_or_404(id)
        bidangName = request.form['namaBidang']
        
        check_bidang = TblBidang.query.filter_by(nama_bidang=bidangName).first()
        check_bidang_status = TblBidang.query.filter_by(status='active').all()
        if check_bidang and check_bidang_status:
            save_log('User %s gagal mengedit bidang!(Nama Duplikat)'% current_user.nama,'misc_gagal')
            flash('Bidang dengan nama (%s) sudah ada, silahkan gunakan nama lain!' % bidangName, 'danger')
            return redirect(url_for('managebidang'))
        
        get_bidang.nama_kategori = bidangName
        get_bidang.keterangan = request.form['keteranganBidang']
        db.session.commit()
        
        save_log('User %s berhasil menambahkan bidang!'% current_user.nama,'edit')
        flash('Bidang  (%s) berhasil diedit!' % bidangName, 'success')
        return redirect(url_for('managebidang'))
    else:
        save_log('User %s gagal menambahkan bidang!(Error)'% current_user.nama,'misc_gagal')
        flash('Gagal edit data Bidang!', 'danger')
        return redirect(url_for('managebidang'))
        
@app.route('/managebidang')
@login_required
def managebidang():
    getallbidang = TblBidang.query.filter_by(status='active').all()
    return render_template('manage_bidang.html', daftarbidang=getallbidang)
    
@app.route('/deletebidang', methods=['POST'])
@login_required
def deletebidang():
    id = request.form['bidangId']
    if request.method == 'POST':
        inactive = 'inactive'
        get_bidang = TblBidang.query.get_or_404(id)
        namabidang = get_bidang.nama_bidang
        get_bidang.status = inactive
        db.session.commit()
        
        save_log('User %s berhasil menghapus bidang!'% current_user.nama,'hapus')
        flash('Bidang (%s) berhasil dihapus!' % namabidang, 'success')
        return redirect(url_for('managebidang'))
    else:
        save_log('User %s gagasl menghapus bidang!'% current_user.nama,'misc_gagal')
        flash('Bidang gagal dihapus!', 'danger')
        return redirect(url_for('managebidang'))

# ++++++++++++++ End Bidang Block +++++++++++++++++++



# ++++++++++++++ Start Dashboard Admin Block +++++++++++++++++++

@app.route('/admindashboard')
@login_required
def admindashboard():
    # get_login_logs = TblLogs.query.filter_by(action='login').order_by(TblLogs.waktu.desc()).all()
    return render_template('admindashboard.html')


@app.route('/api/get_login_logs', methods=['GET'])
def send_data():
    actions = ['login','logout','signin']
    get_login_logs = TblLogs.query.filter(TblLogs.action.in_(actions)).order_by(TblLogs.id_log.desc()).limit(50).all()
    data = []
    for log in get_login_logs:
        data.append({
            'id': log.id_log,
            'message': log.message,
            'waktu': log.waktu.strftime('%H:%M WITA, %d, %B %Y'),
            'action': log.action
        })
    return jsonify(data)


@app.route('/api/get_bucket_data', methods=['GET'])
def get_bucket():
    paginator = s3_client.get_paginator('list_objects_v2')
    total_size = 0
    total_files = 0
    free_tier_limit = 5120
    
    for page in paginator.paginate(Bucket=BUCKET_NAME, Prefix=f'documents_uploads/'):
        if 'Contents' in page:
            for obj in page['Contents']:
                total_files += 1
                total_size += obj['Size']

    total_size = round(total_size / (1024 * 1024), 2)

    usage_percent = min(round((total_size / free_tier_limit) * 100, 2), 100)
    
    return jsonify({
        "total_files": total_files,
        "total_size_mb": total_size,
        "usage_percent": usage_percent
        })
    
@app.route('/api/get_doc_data', methods=['GET'])
def get_doc_log():
    actions = ['dokumen_gagal','dokumen_up_cloud','dokumen_upload','dokumen_edit','dokumen_hapus','dokumen_download']
    get_docs = TblLogs.query.filter(TblLogs.action.in_(actions)).order_by(TblLogs.id_log.desc()).limit(50).all()
    data_doc = []
    for log in get_docs:
        data_doc.append({
            'id': log.id_log,
            'message': log.message,
            'waktu': log.waktu.strftime('%H:%M WITA, %d, %B %Y'),
            'action': log.action
        })
    return jsonify(data_doc)

@app.route('/api/get_misc_data', methods=['GET'])
def get_doc_misc():
    actions = ['tambah','edit','hapus','misc_gagal']
    get_misc = TblLogs.query.filter(TblLogs.action.in_(actions)).order_by(TblLogs.id_log.desc()).limit(50).all()
    data_misc = []
    for log in get_misc:
        data_misc.append({
            'id': log.id_log,
            'message': log.message,
            'waktu': log.waktu.strftime('%H:%M WITA, %d, %B %Y'),
            'action': log.action
        })
    return jsonify(data_misc)
    
# ++++++++++++++ End Dashboard admin Block +++++++++++++++++++



# ++++++++++++++ Start Document Block +++++++++++++++++++

@app.route('/uploaddocform')
@login_required
def uploaddocform():
    getcategory = TblKategoriDokumen.query.filter_by(status='active').all()
    
    active_tags = db.session.query(TblTags.tag_name).distinct().all()
    active_tags = [tag[0] for tag in active_tags]

    return render_template('uploaddocform.html', categories = getcategory, tags=active_tags)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_mime_type(file_path):
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type

@app.route('/upload', methods=['POST'])
@login_required
def upload_new_file():
    title = request.form['dokumenJudul']
    if 'file' not in request.files:
        save_log('User %s gagal upload dokumen!(File tidak ada dalam request)'% current_user.nama,'dokumen_gagal')
        flash('File tidak ada didalam request', 'danger')
        return redirect(url_for('uploaddocform'))

    file = request.files['file']

    if file.filename == '':
        save_log('User %s gagal upload dokumen!(Tidak ada file yang dipilih)'% current_user.nama,'dokumen_gagal')
        flash('Tidak ada file yang dipilih!', 'danger')
        return redirect(url_for('uploaddocform'))

    if not allowed_file(file.filename):
        save_log('User %s gagal upload dokumen!(Extensi file tidak diperbolehkan)'% current_user.nama,'dokumen_gagal')
        flash('Extensi file tidak diperbolehkan!', 'danger')
        return redirect(url_for('uploaddocform'))

    filename = secure_filename(file.filename)
    
    check_document = TblDokumen.query.filter_by(judul_dokumen=title).first()
    check_document_status = TblDokumen.query.filter_by(status='active').all()
    if check_document and check_document_status:
        save_log('User %s gagal upload dokumen!(Nama duplikat)'% current_user.nama,'dokumen_gagal')
        flash('Dokumen dengan nama (%s) sudah ada, silahkan gunakan nama lain!' % title, 'warning')
        return redirect(url_for('uploaddocform'))

    if filename:
        try:
            s3_client.upload_fileobj(
                file,
                BUCKET_NAME,
                f'documents_uploads/{filename}',
            )
            save_log('Dokumen dari user %s berhasil diupload ke dalam cloud!'% current_user.nama,'dokumen_up_cloud')
            print('Upload Sukses!')
        except Exception as e:
            save_log('Dokumen dari user %s gagal diupload ke dalam cloud!'% current_user.nama,'dokumen_gagal')
            print('Upload gagal!')
            return jsonify({'error': str(e)}), 500

        # process document metadatas
        keterangan = request.form['dokumenKeterangan']
        kategori = request.form['pilihKategori']
        id_user = current_user.id_user
        
        query_user = TblUser.query.get_or_404(id_user)
        bidang_user = query_user.id_bidang
        uploader = query_user.id_user
        timenow = get_wib_time()
        set_doc_code = generate_doc_code()
        
        save_to_db = TblDokumen(
            judul_dokumen=title,
            nama_file=filename,
            uploader=uploader,
            bidang_upload=bidang_user,
            tanggal_upload=timenow,
            deskripsi=keterangan,
            url_file='',
            versi='1',
            status='active',
            doc_code=set_doc_code,
            id_kategori=kategori
            )
        db.session.add(save_to_db)
        db.session.commit()
        new_doc_id = save_to_db.id_dokumen
        
        tags = request.form.getlist('selected_tags')
        
        for name in tags:
            tag = TblTags.query.filter_by(tag_name=name, id_dokumen=new_doc_id).first()
            if not tag:
                tag = TblTags(id_dokumen=new_doc_id, tag_name=name)
                db.session.add(tag)
                
        db.session.commit()
        save_log('User %s berhasil upload dokumen!'% current_user.nama,'dokumen_upload', new_doc_id)
        flash('Dokumen %s berhasil di upload!' % title, 'success')
        return redirect(url_for('index'))
    save_log('User %s gagal upload dokumen!'% current_user.nama,'dokumen_gagal', new_doc_id)
    flash('Dokumen %s gagal di upload!' % title, 'danger')
    return redirect(url_for('index'))

@app.route('/mydocuments')
@login_required
def mydocs():
    get_user_id = current_user.id_user
    
    getdocs = db.session.query(TblDokumen) \
    .join(TblUser, TblDokumen.uploader == TblUser.id_user) \
    .join(TblBidang, TblDokumen.bidang_upload == TblBidang.id_bidang) \
    .join(TblKategoriDokumen, TblDokumen.id_kategori == TblKategoriDokumen.id_kategori) \
    .join(TblTags, TblDokumen.id_dokumen == TblTags.id_dokumen) \
    .filter(TblDokumen.status == 'active', TblDokumen.uploader == get_user_id) \
    .group_by(TblDokumen.id_dokumen) \
    .order_by(TblDokumen.tanggal_upload.desc()) \
    .all()
    
    return render_template('mydocs.html', mydocs = getdocs)    

@app.route('/managedocs')
@login_required
def managedocpage():    
    getdocs = db.session.query(TblDokumen) \
    .join(TblUser, TblDokumen.uploader == TblUser.id_user) \
    .join(TblBidang, TblDokumen.bidang_upload == TblBidang.id_bidang) \
    .join(TblKategoriDokumen, TblDokumen.id_kategori == TblKategoriDokumen.id_kategori) \
    .join(TblTags, TblDokumen.id_dokumen == TblTags.id_dokumen) \
    .filter(TblDokumen.status == 'active') \
    .group_by(TblDokumen.id_dokumen) \
    .order_by(TblDokumen.tanggal_upload.desc()) \
    .all()
    
    return render_template('manage_docs.html', mydocs = getdocs)    

@app.route('/mydocuments/edit<int:id>')
@login_required
def editdocpage(id):
    get_doc = TblDokumen.query.get_or_404(id)
    getcategory = TblKategoriDokumen.query.filter_by(status='active', id_kategori=get_doc.id_kategori)
    
    active_tags = (
        db.session.query(TblTags.tag_name)
        .filter(TblTags.id_dokumen == get_doc.id_dokumen)
        .distinct()
        .all()
    )
    active_tags = [tag[0] for tag in active_tags]
    
    return render_template('edit_doc.html', doc=get_doc, categories = getcategory, tags=active_tags) 

@app.route('/mydocuments/edit', methods=['POST'])
@login_required
def editdoc(source=None):
    id_doc = request.form['doc_id']
    if 'file' not in request.files:
        flash('File tidak ada didalam request', 'danger')
        save_log('User %s gagal edit dokumen!(File tidak ada di dalam request)'% current_user.nama,'dokumen_gagal',id_doc)
        if source == 'manage':
            return redirect(url_for('managedocpage'))
        else:
            return redirect(url_for('mydocs'))

    file = request.files['file']

    if file.filename == '':
        save_log('User %s gagal edit dokumen!(Tidak ada file yang dipilih)'% current_user.nama,'dokumen_gagal',id_doc)
        flash('Tidak ada file yang dipilih!', 'danger')
        if source == 'manage':
            return redirect(url_for('managedocpage'))
        else:
            return redirect(url_for('mydocs'))

    if not allowed_file(file.filename):
        save_log('User %s gagal edit dokumen!(Extensi file tidak diperbolehkan)'% current_user.nama,'dokumen_gagal',id_doc)
        flash('Extensi file tidak diperbolehkan!', 'danger')
        if source == 'manage':
            return redirect(url_for('managedocpage'))
        else:
            return redirect(url_for('mydocs'))

    filename = secure_filename(file.filename)


    if filename:
        try:
            s3_client.upload_fileobj(
                file,
                BUCKET_NAME,
                f'documents_uploads/{filename}',
            )
            save_log('User %s berhasil upload dokumen yang sudah diedit ke cloud!'% current_user.nama,'dokumen_up_cloud',id_doc)
            print('Upload Sukses!')
        except Exception as e:
            save_log('User %s gagal upload dokumen!'% current_user.nama,'dokumen_gagal',id_doc)
            print('Upload gagal!')
            return jsonify({'error': str(e)}), 500

        
        get_doc = TblDokumen.query.get_or_404(id_doc)
        get_doc.url_file = ''
        get_doc.nama_file = filename
        get_doc.versi = get_doc.versi + 1
        
        save_to_db_versi = TblVersiDokumen(
            id_dokumen=get_doc.id_dokumen,
            uploader=get_doc.uploader,
            url_file=get_doc.url_file,
            versi=get_doc.versi,
            diupload_pada = get_doc.tanggal_upload,
            status='deleted'
            )
        
        db.session.add(save_to_db_versi)
        db.session.commit()
        save_log('User %s berhasil edit dokumen!'% current_user.nama,'dokumen_edit',id_doc)
        flash('Dokumen berhasil diubah!', 'success')
        if source == 'manage':
            return redirect(url_for('managedocpage'))
        else:
            return redirect(url_for('mydocs'))
    else:
        save_log('User %s gagal edit dokumen!'% current_user.nama,'dokumen_gagal',id_doc)
        flash('Dokumen %s gagal diedit!', 'danger')
        return redirect(url_for('index'))
    
@app.route('/mydocuments/delete', methods=['POST'])
@login_required
def deletedoc(source=None):
    get_doc_id = request.form['doc_id']
    query = TblDokumen.query.get_or_404(get_doc_id)
    
    query.status = 'deleted'
    db.session.commit()
    
    save_log('User %s berhasil menghapus dokumen!'% current_user.nama,'dokumen_hapus',get_doc_id)
    flash('Dokumen berhasil dihapus!', 'success') 
    if source == 'manage':
        return redirect(url_for('managedocpage'))
    else:
        return redirect(url_for('mydocs'))
# ++++++++++++++ End Document Block +++++++++++++++++++



# Log process
def save_log(message, action,document=None):
    user = current_user.id_user
    time = get_wib_time()
    message = message
    action = action
    
    if document:
        query_to_logs = TblLogs(
            user_id=user,
            action=action,
            id_dokumen=document,
            message=message,
            waktu=time
        )
    else:
        query_to_logs = TblLogs(
            user_id=user,
            action=action,
            message=message,
            waktu=time
        )
    db.session.add(query_to_logs)
    db.session.commit()

    
@app.route('/get-download-url/<path:file_name>')
def get_download_url(file_name):
    try:
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BUCKET_NAME,
                'Key': f'documents_uploads/{file_name}'
            },
            ExpiresIn=300
        )
        save_log('User %s mendownload dokumen %s'% current_user.nama % file_name,'dokumen_download')
        return redirect(presigned_url)
    except Exception as e:
        return f"Error: {str(e)}", 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
