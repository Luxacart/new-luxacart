from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-with-a-secure-random-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///luxacart.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(300), nullable=True)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/product/<int:pid>')
def product_detail(pid):
    p = Product.query.get_or_404(pid)
    return render_template('product.html', product=p)

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') or None
        phone = request.form.get('phone') or None
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter((User.username==username)|(User.email==email)|(User.phone==phone)).first():
            flash('User already exists with same username/email/phone', 'warning')
            return redirect(url_for('signup'))
        user = User(username=username, email=email, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # username / email / phone
        password = request.form.get('password')
        user = None
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        elif identifier.isdigit():
            user = User.query.filter_by(phone=identifier).first()
        else:
            user = User.query.filter_by(username=identifier).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin', methods=['GET','POST'])
def admin():
    if request.method == 'POST':
        title = request.form.get('title')
        price = float(request.form.get('price') or 0)
        desc = request.form.get('description')
        image = request.form.get('image')
        p = Product(title=title, price=price, description=desc, image=image)
        db.session.add(p)
        db.session.commit()
        flash('Product added', 'success')
        return redirect(url_for('admin'))
    products = Product.query.all()
    return render_template('admin.html', products=products)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)