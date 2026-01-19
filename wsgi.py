from app import app, db
from app import User, Araba
import logging

# Create database tables
with app.app_context():
    db.create_all()  # Tables will not be created if they already exist

    # Add admin user (if not exists)
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True
        )
        admin.set_password('admin123')  # Securely set admin password
        db.session.add(admin)
        db.session.commit()
        logging.info("Admin user successfully added.")
    
    # Add sample cars (if not exists)
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
        araba = Araba.query.filter_by(marka=araba_data['marka'], model=araba_data['model']).first()
        if not araba:
            araba = Araba(**araba_data)
            db.session.add(araba)

    db.session.commit()
    logging.info("Sample cars successfully added.")

if __name__ == "__main__":
    app.run()
