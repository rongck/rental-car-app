from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import mysql.connector
from werkzeug.utils import secure_filename
from functools import wraps
import logging
import secrets
from sqlalchemy import text
from sqlalchemy.sql import func

# Load .env file
load_dotenv()

# Create Flask application
app = Flask(__name__)
app.debug = False  # Disable debug mode

# Logging configuration
logging.basicConfig(
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.log'),
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret-key-here')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'images')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# MySQL connection info
DB_USER = os.getenv('DB_USER', 'admin')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'araba_kiralama')

def validate_dates(baslangic, bitis):
    """Validates rental dates"""
    if baslangic >= bitis:
        raise ValueError("Start date must be before end date.")
    if baslangic < datetime.now():
        raise ValueError("Start date cannot be in the past.")
    if bitis < datetime.now():
        raise ValueError("End date cannot be in the past.")
    if (bitis - baslangic).days > 30:
        raise ValueError("Rental period cannot be longer than 30 days.")

# SQLAlchemy connection URL
SQLALCHEMY_DATABASE_URI = f'mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    kiralamalar = db.relationship('Kiralama', backref='kullanici', lazy=True)
    reset_token = db.Column(db.String(255))
    reset_token_expires = db.Column(db.DateTime)

    def set_password(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

class Araba(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    marka = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    yil = db.Column(db.Integer, nullable=False)
    gunluk_fiyat = db.Column(db.Float, nullable=False)
    resim_url = db.Column(db.String(200))
    aciklama = db.Column(db.Text)
    kategori = db.Column(db.String(50), nullable=False, default='Other')
    kiralamalar = db.relationship('Kiralama', backref='araba', lazy=True)

class Kiralama(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    baslangic_tarihi = db.Column(db.DateTime, nullable=False)
    bitis_tarihi = db.Column(db.DateTime, nullable=False)
    toplam_fiyat = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    araba_id = db.Column(db.Integer, db.ForeignKey('araba.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def check_database():
    """Check and report cars in the database"""
    with app.app_context():
        try:
            arabalar = Araba.query.all()
            logging.info(f"{len(arabalar)} cars found in the database.")
            for araba in arabalar:
                logging.info(f"{araba.marka} {araba.model}: {araba.resim_url}")
            return arabalar
        except Exception as e:
            logging.error(f"Error occurred while checking database: {e}")
            raise e

def reset_database():
    """Resets and recreates the database"""
    try:
        # Create MySQL connection
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = connection.cursor()

        # Drop and recreate database
        cursor.execute(f"DROP DATABASE IF EXISTS {DB_NAME}")
        cursor.execute(f"CREATE DATABASE {DB_NAME}")
        logging.info(f"Database '{DB_NAME}' successfully reset.")

        cursor.close()
        connection.close()

        # Create tables with SQLAlchemy
        with app.app_context():
            db.create_all()
            logging.info("All tables successfully created.")
            
            # Create admin user
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            logging.info("Admin user created.")
            
            # Add sample cars
            seed_database()
            logging.info("Sample cars added.")

    except Exception as e:
        logging.error(f"Error occurred while resetting database: {e}")
        raise e

def handle_image_upload(resim, default_filename='default.jpg'):
    if resim and allowed_file(resim.filename):
        try:
            # Secure filename
            filename = secure_filename(resim.filename)
            
            # Check and fix file extension
            if '.' not in filename:
                filename = f"{filename}.jpg"
            elif filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
                filename = f"{filename.rsplit('.', 1)[0]}.jpg"
            
            # Create unique filename
            unique_filename = f"{int(datetime.now().timestamp())}_{filename}"
            
            # Build full image path
            resim_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Ensure upload folder exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            # Set folder permissions
            os.chmod(app.config['UPLOAD_FOLDER'], 0o755)
            
            # Save image
            resim.save(resim_path)
            logging.info(f"Image saved successfully: {resim_path}")
            
            # Set file permissions
            os.chmod(resim_path, 0o644)
            
            # Change owner to www-data
            os.system(f"sudo chown www-data:www-data {resim_path}")
            os.system(f"sudo chown www-data:www-data {app.config['UPLOAD_FOLDER']}")
            
            # Verify file exists and log permissions
            if os.path.exists(resim_path):
                stat = os.stat(resim_path)
                logging.info(f"Image file created successfully: {resim_path}")
                logging.info(f"File permissions: {oct(stat.st_mode)}")
                logging.info(f"File owner: {stat.st_uid}:{stat.st_gid}")
                logging.info(f"Filename: {unique_filename}")
                return unique_filename
            else:
                logging.error(f"Image file could not be created: {resim_path}")
                return default_filename
                
        except Exception as e:
            logging.error(f"Error occurred while uploading image: {e}")
            return default_filename
    else:
        logging.warning(f"Invalid image format or no image uploaded: {resim.filename if resim else 'No file'}")
        return default_filename

def delete_image(filename):
    if filename and filename != 'default.jpg':
        try:
            resim_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(resim_path):
                os.remove(resim_path)
                logging.info(f"Image deleted: {resim_path}")
        except Exception as e:
            logging.error(f"Error occurred while deleting image: {e}")

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Routes
@app.route('/')
def index():
    try:
        arabalar = Araba.query.all()
        logging.info(f"Homepage loaded. {len(arabalar)} cars found.")
        return render_template('index.html', arabalar=arabalar)
    except Exception as e:
        logging.error(f"Error occurred while loading homepage: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/admin/panel')
@admin_required
def admin_panel():
    try:
        arabalar = Araba.query.all()
        kiralamalar = Kiralama.query.all()
        kullanicilar = User.query.all()
        return render_template('admin_panel.html', 
                             arabalar=arabalar, 
                             kiralamalar=kiralamalar, 
                             kullanicilar=kullanicilar)
    except Exception as e:
        logging.error(f"Error occurred while loading admin panel: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/admin/araba/ekle', methods=['GET', 'POST'])
@admin_required
def araba_ekle():
    if request.method == 'POST':
        try:
            # Get form data
            marka = request.form.get('marka')
            model = request.form.get('model')
            yil = request.form.get('yil')
            gunluk_fiyat = request.form.get('gunluk_fiyat')
            aciklama = request.form.get('aciklama', '')

            # Validate required fields
            if not all([marka, model, yil, gunluk_fiyat]):
                flash('Please fill in all required fields!', 'error')
                return redirect(url_for('araba_ekle'))
                
            # Image upload
            resim_url = 'default.jpg'
            if 'resim' in request.files:
                resim = request.files['resim']
                if resim.filename:
                    resim_url = handle_image_upload(resim)
                    logging.info(f"Uploaded image file: {resim_url}")

            # Create new car
            yeni_araba = Araba(
                marka=marka,
                model=model,
                yil=int(yil),
                gunluk_fiyat=float(gunluk_fiyat),
                resim_url=resim_url,
                aciklama=aciklama
            )

            # Save to database
            db.session.add(yeni_araba)
            db.session.commit()
            
            logging.info(f"New car added: {yeni_araba.marka} {yeni_araba.model}")
            flash('Car successfully added!', 'success')
            return redirect(url_for('admin_panel'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error occurred while adding car: {e}")
            flash('An error occurred while adding the car!', 'error')
            return redirect(url_for('araba_ekle'))

    return render_template('araba_ekle.html')

@app.route('/admin/araba/sil/<int:id>')
@admin_required
def araba_sil(id):
    try:
        araba = db.session.get(Araba, id)
        if not araba:
            flash('Car not found!', 'error')
            return redirect(url_for('admin_panel'))
            
        # Check rentals
        aktif_kiralamalar = Kiralama.query.filter_by(araba_id=id).first()
        
        if aktif_kiralamalar:
            flash('This car has active rental records. You must delete rentals first!', 'error')
            return redirect(url_for('admin_panel'))
        
        # Delete image
        delete_image(araba.resim_url)
        
        # Delete car
        db.session.delete(araba)
        db.session.commit()
        
        flash('Car successfully deleted!', 'success')
        return redirect(url_for('admin_panel'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred while deleting car: {e}")
        flash('An error occurred while deleting the car!', 'error')
        return redirect(url_for('admin_panel'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Check username and email
            if User.query.filter_by(username=username).first():
                flash('This username is already in use.', 'error')
                logging.warning(f"Registration failed: Username already exists - {username}")
                return redirect(url_for('register'))
                
            if User.query.filter_by(email=email).first():
                flash('This email address is already in use.', 'error')
                logging.warning(f"Registration failed: Email already exists - {email}")
                return redirect(url_for('register'))
            
            # Create user
            user = User(
                username=username,
                email=email,
                is_admin=False
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! You can log in now.', 'success')
            logging.info(f"New user registered successfully: {username}")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            logging.error(f"Registration error: {e}")
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            user = User.query.filter_by(username=username).first()
            
            if not user:
                flash('No user found with this username.', 'error')
                logging.warning(f"Login failed: User not found - {username}")
                return redirect(url_for('login'))
            
            if not user.password_hash:
                flash('User password not found. Please contact admin.', 'error')
                logging.error(f"User password not found: {username}")
                return redirect(url_for('login'))
            
            if not user.check_password(password):
                flash('Incorrect password.', 'error')
                logging.warning(f"Login failed: Incorrect password - {username}")
                return redirect(url_for('login'))
            
            login_user(user)
            flash('Successfully logged in!', 'success')
            logging.info(f"User logged in successfully: {username}")
            return redirect(url_for('index'))
            
        except Exception as e:
            flash('An error occurred while logging in. Please try again.', 'error')
            logging.error(f"Login error: {e}")
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/araba/<int:id>')
def araba_detay(id):
    araba = db.session.get(Araba, id)
    if not araba:
        flash('Car not found!', 'error')
        return redirect(url_for('index'))
    return render_template('araba_detay.html', araba=araba)

@app.route('/kirala/<int:araba_id>', methods=['GET', 'POST'])
@login_required
def kirala(araba_id):
    araba = Araba.query.get_or_404(araba_id)
    
    if request.method == 'POST':
        try:
            baslangic = datetime.strptime(request.form.get('baslangic'), '%Y-%m-%d')
            bitis = datetime.strptime(request.form.get('bitis'), '%Y-%m-%d')
            
            validate_dates(baslangic, bitis)
            
            # Check overlapping rentals
            mevcut_kiralamalar = Kiralama.query.filter(
                Kiralama.araba_id == araba_id,
                Kiralama.baslangic_tarihi <= bitis,
                Kiralama.bitis_tarihi >= baslangic
            ).first()
            
            if mevcut_kiralamalar:
                flash('The car is already rented for the selected dates!')
                return redirect(url_for('kirala', araba_id=araba_id))
            
            gun_farki = (bitis - baslangic).days
            toplam_fiyat = araba.gunluk_fiyat * gun_farki
            
            kiralama = Kiralama(
                baslangic_tarihi=baslangic,
                bitis_tarihi=bitis,
                toplam_fiyat=toplam_fiyat,
                user_id=current_user.id,
                araba_id=araba.id
            )
            
            db.session.add(kiralama)
            db.session.commit()
            
            flash('Car successfully rented!')
            return redirect(url_for('index'))
            
        except ValueError as e:
            flash(str(e))
            return redirect(url_for('kirala', araba_id=araba_id))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error occurred during rental: {e}")
            flash('An error occurred during the rental process!')
            return redirect(url_for('kirala', araba_id=araba_id))
    
    return render_template('kirala.html', araba=araba)

@app.route('/kiralarim')
@login_required
def kiralarim():
    try:
        kiralamalar = Kiralama.query.filter_by(user_id=current_user.id).order_by(Kiralama.baslangic_tarihi.desc()).all()
        return render_template('kiralarim.html', kiralamalar=kiralamalar, datetime=datetime)
    except Exception as e:
        logging.error(f"Error occurred while loading rentals list: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/kiralama/iptal/<int:id>')
@login_required
def kiralama_iptal(id):
    try:
        kiralama = db.session.get(Kiralama, id)
        if not kiralama:
            flash('Rental not found!', 'error')
            return redirect(url_for('kiralarim'))
        
        # Check ownership
        if kiralama.user_id != current_user.id:
            flash('You are not authorized to cancel this rental!', 'error')
            return redirect(url_for('kiralarim'))
        
        # Check if rental started
        if kiralama.baslangic_tarihi <= datetime.now():
            flash('A started rental cannot be canceled!', 'error')
            return redirect(url_for('kiralarim'))
        
        db.session.delete(kiralama)
        db.session.commit()
        
        flash('Rental successfully canceled!', 'success')
        return redirect(url_for('kiralarim'))
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred while canceling rental: {e}")
        flash('An error occurred while canceling the rental!', 'error')
        return redirect(url_for('kiralarim'))

@app.route('/arama')
def araba_ara():
    try:
        query = request.args.get('q', '')
        min_fiyat = request.args.get('min_fiyat', type=float)
        max_fiyat = request.args.get('max_fiyat', type=float)
        min_yil = request.args.get('min_yil', type=int)
        max_yil = request.args.get('max_yil', type=int)
        
        arabalar = Araba.query
        
        if query:
            arabalar = arabalar.filter(
                db.or_(
                    Araba.marka.ilike(f'%{query}%'),
                    Araba.model.ilike(f'%{query}%')
                )
            )
        
        if min_fiyat is not None:
            arabalar = arabalar.filter(Araba.gunluk_fiyat >= min_fiyat)
        
        if max_fiyat is not None:
            arabalar = arabalar.filter(Araba.gunluk_fiyat <= max_fiyat)
        
        if min_yil is not None:
            arabalar = arabalar.filter(Araba.yil >= min_yil)
        
        if max_yil is not None:
            arabalar = arabalar.filter(Araba.yil <= max_yil)
        
        arabalar = arabalar.all()
        return render_template('arama.html', arabalar=arabalar, query=query)
    except Exception as e:
        logging.error(f"Error occurred while searching: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/istatistik')
@login_required
def istatistik():
    try:
        # Total rentals count
        toplam_kiralama = Kiralama.query.count()
        
        # Total revenue
        toplam_gelir = db.session.query(func.sum(Kiralama.toplam_fiyat)).scalar() or 0
        
        # Most rented cars
        en_cok_kiralanan = db.session.query(
            Araba.model,
            func.count(Kiralama.id).label('kiralama_sayisi')
        ).join(Kiralama).group_by(Araba.model).order_by(func.count(Kiralama.id).desc()).limit(5).all()
        
        # Monthly rentals statistics
        aylik_kiralama = db.session.query(
            func.date_format(Kiralama.baslangic_tarihi, '%Y-%m').label('month'),
            func.count(Kiralama.id).label('rental_count')
        ).group_by('month').order_by('month').all()
        
        # Distribution by category
        kategori_dagilimi = db.session.query(
            Araba.kategori,
            func.count(Araba.id).label('car_count')
        ).group_by(Araba.kategori).all()
        
        return render_template('istatistik.html',
                             toplam_kiralama=toplam_kiralama,
                             toplam_gelir=toplam_gelir,
                             en_cok_kiralanan=en_cok_kiralanan,
                             aylik_kiralama=aylik_kiralama,
                             kategori_dagilimi=kategori_dagilimi)
    except Exception as e:
        logging.error(f"Error occurred while loading statistics page: {e}")
        return render_template('error.html', error=str(e)), 500

@app.route('/profil', methods=['GET', 'POST'])
@login_required
def profil():
    if request.method == 'POST':
        try:
            # Update email
            yeni_email = request.form.get('email')
            if yeni_email and yeni_email != current_user.email:
                if User.query.filter_by(email=yeni_email).first():
                    flash('This email address is already in use!', 'error')
                    return redirect(url_for('profil'))
                current_user.email = yeni_email
            
            # Update password
            yeni_sifre = request.form.get('yeni_sifre')
            if yeni_sifre:
                mevcut_sifre = request.form.get('mevcut_sifre')
                if not current_user.check_password(mevcut_sifre):
                    flash('Current password is incorrect!', 'error')
                    return redirect(url_for('profil'))
                current_user.set_password(yeni_sifre)
            
            db.session.commit()
            flash('Profile successfully updated!', 'success')
            return redirect(url_for('profil'))
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error occurred while updating profile: {e}")
            flash('An error occurred while updating the profile!', 'error')
            return redirect(url_for('profil'))
    
    return render_template('profil.html')

@app.route('/sifremi-unuttum', methods=['GET', 'POST'])
def sifremi_unuttum():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            user = User.query.filter_by(email=email).first()
            
            if user:
                # Create unique token
                token = secrets.token_urlsafe(32)
                user.reset_token = token
                user.reset_token_expires = datetime.now() + timedelta(hours=1)
                db.session.commit()
                
                # Email sending will be implemented here
                # Example: send_reset_email(user.email, token)
                
                flash('A password reset link has been sent to your email address.', 'success')
            else:
                flash('No user found with this email address.', 'error')
            
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error occurred during password reset request: {e}")
            flash('An error occurred during the password reset process!', 'error')
            return redirect(url_for('sifremi_unuttum'))
    
    return render_template('sifremi_unuttum.html')

@app.route('/sifre-sifirla/<token>', methods=['GET', 'POST'])
def sifre_sifirla(token):
    try:
        user = User.query.filter_by(reset_token=token).first()
        
        if not user or not user.reset_token_expires or user.reset_token_expires < datetime.now():
            flash('Invalid or expired password reset link!', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            yeni_sifre = request.form.get('yeni_sifre')
            if yeni_sifre:
                user.set_password(yeni_sifre)
                user.reset_token = None
                user.reset_token_expires = None
                db.session.commit()
                
                flash('Your password has been successfully updated! You can log in now.', 'success')
                return redirect(url_for('login'))
        
        return render_template('sifre_sifirla.html')
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred during password reset: {e}")
        flash('An error occurred during the password reset process!', 'error')
        return redirect(url_for('login'))

# Database update function
def update_database():
    try:
        with app.app_context():
            # Check if columns exist
            result = db.session.execute(text("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'user' 
                AND COLUMN_NAME IN ('reset_token', 'reset_token_expires')
            """))
            existing_columns = [row[0] for row in result]
            
            # Add missing columns
            if 'reset_token' not in existing_columns:
                db.session.execute(text("""
                    ALTER TABLE user 
                    ADD COLUMN reset_token VARCHAR(100)
                """))
            
            if 'reset_token_expires' not in existing_columns:
                db.session.execute(text("""
                    ALTER TABLE user 
                    ADD COLUMN reset_token_expires DATETIME
                """))
            
            # Check category column in araba table
            result = db.session.execute(text("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'araba' 
                AND COLUMN_NAME = 'kategori'
            """))
            if not result.fetchone():
                db.session.execute(text("""
                    ALTER TABLE araba 
                    ADD COLUMN kategori VARCHAR(50) NOT NULL DEFAULT 'Diğer'
                """))
            
            db.session.commit()
        print("Database successfully updated.")
    except Exception as e:
        db.session.rollback()
        print(f"Error occurred while updating database: {e}")

def seed_database():
    """Add sample cars to the database"""
    try:
        # Add sample cars
        arabalar = [
            {
                'marka': 'BMW',
                'model': '320i',
                'yil': 2022,
                'gunluk_fiyat': 500,
                'resim_url': 'bmw-320i.jpg',
                'aciklama': 'Luxury and comfortable BMW 320i',
                'kategori': 'Luxury'
            },
            {
                'marka': 'Mercedes',
                'model': 'C200',
                'yil': 2023,
                'gunluk_fiyat': 550,
                'resim_url': 'mercedes-c200.jpg',
                'aciklama': 'Stylish and modern Mercedes C200',
                'kategori': 'Luxury'
            },
            {
                'marka': 'Audi',
                'model': 'A4',
                'yil': 2022,
                'gunluk_fiyat': 480,
                'resim_url': 'audi-a4.jpg',
                'aciklama': 'Sporty and dynamic Audi A4',
                'kategori': 'Luxury'
            },
            {
                'marka': 'Volkswagen',
                'model': 'Passat',
                'yil': 2023,
                'gunluk_fiyat': 400,
                'resim_url': 'volkswagen-passat.jpg',
                'aciklama': 'Economical and reliable VW Passat',
                'kategori': 'Mid Segment'
            },
            {
                'marka': 'Tesla',
                'model': 'Model X',
                'yil': 2023,
                'gunluk_fiyat': 800,
                'resim_url': 'Tesla-ModelX-2016-01.jpg',
                'aciklama': 'Electric and modern Tesla Model X',
                'kategori': 'Electric'
            }
        ]
        
        # Add cars to the database
        for araba_data in arabalar:
            araba = Araba(**araba_data)
            db.session.add(araba)
        
        db.session.commit()
        logging.info("Sample cars successfully added.")
        
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error occurred while adding sample cars: {e}")
        raise e

def init_database():
    """Initialize database and run necessary checks"""
    try:
        with app.app_context():
            db.create_all()
            logging.info("Database tables checked/created.")
            
            # Apply database updates
            update_database()

            # Ensure admin user exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    is_admin=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logging.info("Admin user created.")
            
            # Seed cars if empty
            if not Araba.query.first():
                seed_database()
                logging.info("Sample cars added.")
            
            logging.info("Database initialization completed.")

    except Exception as e:
        logging.error(f"Error occurred while initializing database: {e}")
        raise e

def create_app():
    """Create and configure the Flask app"""
    try:
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        init_database()
        return app
    except Exception as e:
        logging.error(f"Error occurred while creating app: {e}")
        raise e

if __name__ == '__main__':
    try:
        app = create_app()
        app.run(host='0.0.0.0', port=8000, debug=False)
    except Exception as e:
        logging.error(f"Error occurred while starting app: {e}")
        raise e
