# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from functools import wraps
from sqlalchemy.orm import joinedload
from sqlalchemy import func, or_
import json

# Initialize Flask application
app = Flask(__name__)

# Configure database and upload folder
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'best_angkor_piling.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_strong_and_random_secret_key_for_production')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Initialize SQLAlchemy and Flask-Login
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Pile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pile_type = db.Column(db.String(100), nullable=False)
    size = db.Column(db.String(100), nullable=False)
    length = db.Column(db.Float, nullable=False)
    sku = db.Column(db.String(100), unique=True, nullable=False)
    current_stock = db.Column(db.Integer, default=0)
    sale_price_per_meter = db.Column(db.Float, default=0.0)
    average_cost_per_meter = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)
    transactions = db.relationship('Transaction', backref='pile', lazy=True, cascade="all, delete-orphan")

class CustomerSite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)
    transactions = db.relationship('Transaction', backref='customer_site', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pile_id = db.Column(db.Integer, db.ForeignKey('pile.id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('customer_site.id'), nullable=True)
    transaction_type = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_per_meter_at_transaction = db.Column(db.Float, nullable=False, default=0.0)
    total_value = db.Column(db.Float, nullable=False, default=0.0)
    cost_of_goods_sold = db.Column(db.Float, default=0.0)
    transport_fee = db.Column(db.Float, default=0.0)
    crane_fee = db.Column(db.Float, default=0.0)
    transaction_date = db.Column(db.DateTime, default=datetime.now)
    notes = db.Column(db.Text)

class ExpenseCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    expenses = db.relationship('Expense', backref='category', lazy=True, cascade="all, delete-orphan")

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    expense_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    category_id = db.Column(db.Integer, db.ForeignKey('expense_category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='expenses', lazy=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(100), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref='audit_logs', lazy=True)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

# --- Helper Functions and Decorators ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

@app.context_processor
def inject_global_vars():
    low_stock_setting = Setting.query.filter_by(key='low_stock_threshold').first()
    background_image_setting = Setting.query.filter_by(key='background_image').first()
    return dict(
        current_year=datetime.now().year,
        low_stock_threshold=int(low_stock_setting.value) if low_stock_setting else 10,
        background_image_filename=background_image_setting.value if background_image_setting else None
    )

@app.before_request
def before_request(): g.db = db.session

def role_required(roles):
    if not isinstance(roles, list): roles = [roles]
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "info")
                return redirect(url_for('login', next=request.url))
            if current_user.role not in roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit_event(action, entity_type=None, entity_id=None, details=None):
    log = AuditLog(user_id=current_user.id if current_user.is_authenticated else None, username=current_user.username if current_user.is_authenticated else 'Guest', action=action, entity_type=entity_type, entity_id=entity_id, details=details)
    db.session.add(log)
    db.session.commit()

# --- Core Routes ---
@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/')
@login_required
def index():
    low_stock_threshold = g.get('low_stock_threshold', 10)
    low_stock_piles = Pile.query.filter(Pile.current_stock < low_stock_threshold).all()
    recent_transactions = Transaction.query.options(joinedload(Transaction.pile)).order_by(Transaction.transaction_date.desc()).limit(5).all()
    all_piles = Pile.query.all()
    stock_value_data = {'labels': [p.sku for p in all_piles if p.current_stock > 0], 'values': [p.current_stock * p.length * p.average_cost_per_meter for p in all_piles if p.current_stock > 0]}
    top_stocked_piles = sorted(all_piles, key=lambda p: p.current_stock * p.length, reverse=True)[:5]
    top_stock_data = {'labels': [p.sku for p in top_stocked_piles], 'values': [p.current_stock * p.length for p in top_stocked_piles]}
    return render_template('index.html', piles=all_piles, customer_sites=CustomerSite.query.all(), low_stock_piles=low_stock_piles, recent_transactions=recent_transactions, stock_value_data=json.dumps(stock_value_data), top_stock_data=json.dumps(top_stock_data))

# --- Pile Routes ---
@app.route('/piles')
@login_required
@role_required(['admin', 'manager', 'stock_keeper'])
def manage_piles():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '')
    piles_query = Pile.query.order_by(Pile.sku.asc())
    if search_term:
        piles_query = piles_query.filter(or_(Pile.sku.ilike(f'%{search_term}%'), Pile.pile_type.ilike(f'%{search_term}%'), Pile.size.ilike(f'%{search_term}%')))
    pagination = piles_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('piles.html', piles=pagination.items, pagination=pagination, search_term=search_term)

@app.route('/add_pile', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager'])
def add_pile():
    if request.method == 'POST':
        new_pile = Pile(pile_type=request.form['pile_type'], size=request.form['size'], length=float(request.form['length']), sku=request.form['sku'], sale_price_per_meter=float(request.form['sale_price_per_meter']), description=request.form.get('description'), average_cost_per_meter=0)
        db.session.add(new_pile)
        db.session.commit()
        log_audit_event('add_pile', 'Pile', new_pile.id, f'Added new pile: {new_pile.sku}')
        flash('Pile added successfully!', 'success')
        return redirect(url_for('manage_piles'))
    return render_template('add_pile.html')

@app.route('/edit_pile/<int:pile_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager'])
def edit_pile(pile_id):
    pile = Pile.query.get_or_404(pile_id)
    if request.method == 'POST':
        pile.pile_type = request.form['pile_type']
        pile.size = request.form['size']
        pile.length = float(request.form['length'])
        pile.sku = request.form['sku']
        pile.sale_price_per_meter = float(request.form['sale_price_per_meter'])
        pile.description = request.form.get('description')
        db.session.commit()
        flash('Pile updated successfully!', 'success')
        return redirect(url_for('manage_piles'))
    transactions = Transaction.query.filter_by(pile_id=pile_id).order_by(Transaction.transaction_date.desc()).all()
    return render_template('edit_piles.html', pile=pile, transactions=transactions)

@app.route('/delete_pile/<int:pile_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_pile(pile_id):
    pile = Pile.query.get_or_404(pile_id)
    db.session.delete(pile)
    db.session.commit()
    log_audit_event('delete_pile', 'Pile', pile_id, f'Deleted pile {pile.sku}')
    flash('Pile and associated transactions deleted successfully!', 'success')
    return redirect(url_for('manage_piles'))

# --- Customer Site Routes ---
@app.route('/sites')
@login_required
@role_required(['admin', 'manager'])
def manage_sites():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '')
    sites_query = CustomerSite.query.order_by(CustomerSite.name.asc())
    if search_term:
        sites_query = sites_query.filter(or_(CustomerSite.name.ilike(f'%{search_term}%'), CustomerSite.address.ilike(f'%{search_term}%'), CustomerSite.phone.ilike(f'%{search_term}%')))
    pagination = sites_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('customer_sites.html', customer_sites=pagination.items, pagination=pagination, search_term=search_term)

@app.route('/add_customer_site', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager'])
def add_customer_site():
    if request.method == 'POST':
        new_site = CustomerSite(name=request.form['name'], address=request.form.get('address'), phone=request.form.get('phone'))
        db.session.add(new_site)
        db.session.commit()
        log_audit_event('add_customer_site', 'CustomerSite', new_site.id, f'Added new site: {new_site.name}')
        flash('Customer Site added successfully!', 'success')
        return redirect(url_for('manage_sites'))
    return render_template('add_customer_site.html')

@app.route('/edit_customer_site/<int:site_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager'])
def edit_customer_site(site_id):
    site = CustomerSite.query.get_or_404(site_id)
    if request.method == 'POST':
        site.name = request.form['name']
        site.address = request.form.get('address')
        site.phone = request.form.get('phone')
        db.session.commit()
        flash('Customer Site updated successfully!', 'success')
        return redirect(url_for('manage_sites'))
    return render_template('edit_customer_site.html', site=site)

@app.route('/delete_customer_site/<int:site_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_customer_site(site_id):
    site = CustomerSite.query.get_or_404(site_id)
    if site.transactions:
        flash('Cannot delete site with associated transactions.', 'error')
        return redirect(url_for('manage_sites'))
    db.session.delete(site)
    db.session.commit()
    log_audit_event('delete_customer_site', 'CustomerSite', site_id, f'Deleted site: {site.name}')
    flash('Customer Site deleted successfully!', 'success')
    return redirect(url_for('manage_sites'))

# --- Transaction and Invoice Routes ---
@app.route('/transactions')
@login_required
@role_required(['admin', 'manager', 'stock_keeper'])
def manage_transactions():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search', '')
    transactions_query = Transaction.query.options(joinedload(Transaction.pile), joinedload(Transaction.customer_site)).order_by(Transaction.transaction_date.desc())
    if search_term:
        transactions_query = transactions_query.join(Pile).join(CustomerSite, isouter=True).filter(or_(Pile.sku.ilike(f'%{search_term}%'), CustomerSite.name.ilike(f'%{search_term}%'), Transaction.notes.ilike(f'%{search_term}%')))
    pagination = transactions_query.paginate(page=page, per_page=10, error_out=False)
    return render_template('transactions.html', transactions=pagination.items, pagination=pagination, search_term=search_term)

@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'stock_keeper'])
def add_transaction():
    piles = Pile.query.order_by(Pile.sku).all()
    piles_data = {p.id: {'sale_price_per_meter': p.sale_price_per_meter} for p in piles}
    customer_sites = CustomerSite.query.order_by(CustomerSite.name).all()
    if request.method == 'POST':
        pile_id = request.form.get('pile_id')
        transaction_date_str = request.form.get('transaction_date')
        try:
            transaction_date = datetime.strptime(transaction_date_str, '%Y-%m-%d')
        except (ValueError, TypeError):
            transaction_date = datetime.now()
        
        total_length_input = float(request.form.get('total_length', 0))
        price_per_meter = float(request.form.get('price_per_meter_at_transaction', 0))
        transaction_type = request.form.get('transaction_type')
        transport_fee = float(request.form.get('transport_fee', 0))
        crane_fee = float(request.form.get('crane_fee', 0))
        notes = request.form.get('notes')
        site_id = request.form.get('site_id')

        if not pile_id:
            flash('Please select a pile.', 'error')
            return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites, piles_data=json.dumps(piles_data))
        
        pile = Pile.query.get_or_404(pile_id)
        if pile.length <= 0 or (total_length_input > 0 and total_length_input % pile.length != 0):
            flash(f'ប្រវែងសរុប ({total_length_input}m) មិនត្រឹមត្រូវសម្រាប់សសរប្រវែង {pile.length}m។', 'error')
            return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites, piles_data=json.dumps(piles_data))
        
        quantity = int(total_length_input / pile.length) if pile.length > 0 else 0
        if quantity <= 0:
            flash('សូមបញ្ចូលប្រវែងសរុបឱ្យបានត្រឹមត្រូវ។', 'error')
            return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites, piles_data=json.dumps(piles_data))
        
        pile_value = price_per_meter * total_length_input
        total_value = pile_value + transport_fee + crane_fee
        cogs_for_this_transaction = 0.0

        if transaction_type == 'in':
            total_value = pile_value
            total_existing_length = pile.current_stock * pile.length
            total_existing_cost_value = total_existing_length * pile.average_cost_per_meter
            combined_length = total_existing_length + total_length_input
            combined_cost_value = total_existing_cost_value + total_value
            if combined_length > 0:
                pile.average_cost_per_meter = combined_cost_value / combined_length
            else:
                pile.average_cost_per_meter = price_per_meter
            pile.current_stock += quantity
        elif transaction_type == 'out':
            if pile.current_stock < quantity:
                flash(f'Not enough stock for {pile.sku}. Current stock: {pile.current_stock}', 'error')
                return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites, piles_data=json.dumps(piles_data))
            cogs_for_this_transaction = total_length_input * pile.average_cost_per_meter
            pile.current_stock -= quantity

        new_transaction = Transaction(
            pile_id=pile_id, site_id=site_id if site_id else None, transaction_type=transaction_type, quantity=quantity,
            price_per_meter_at_transaction=price_per_meter, total_value=total_value, cost_of_goods_sold=cogs_for_this_transaction,
            transport_fee=transport_fee, crane_fee=crane_fee, notes=notes, transaction_date=transaction_date
        )
        db.session.add(new_transaction)
        db.session.commit()
        log_audit_event('add_transaction', 'Transaction', new_transaction.id, f'{transaction_type.capitalize()} {quantity} of {pile.sku}. Total: ${total_value}')
        flash('Transaction added successfully!', 'success')
        return redirect(url_for('manage_transactions'))
    
    return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites, piles_data=json.dumps(piles_data))

@app.route('/invoice/<int:transaction_id>')
@login_required
def view_invoice(transaction_id):
    transaction = Transaction.query.options(joinedload(Transaction.pile), joinedload(Transaction.customer_site)).get_or_404(transaction_id)
    if transaction.transaction_type != 'out':
        flash('Invoices can only be generated for "Out" (Sold) transactions.', 'warning')
        return redirect(url_for('manage_transactions'))
    return render_template('invoice.html', transaction=transaction)
    
@app.route('/edit_transaction/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager'])
def edit_transaction(transaction_id):
    flash('Editing transactions is disabled to maintain cost accuracy. Please create a new adjustment transaction.', 'warning')
    return redirect(url_for('manage_transactions'))

@app.route('/delete_transaction/<int:transaction_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    pile = transaction.pile
    if transaction.transaction_type == 'in':
        if pile.current_stock >= transaction.quantity:
            pile.current_stock -= transaction.quantity
        else:
            pile.current_stock = 0
            flash(f'Warning: Stock for {pile.sku} went negative after reverting transaction. Set to 0.', 'warning')
    elif transaction.transaction_type == 'out':
        pile.current_stock += transaction.quantity
    flash('Transaction deleted and stock reverted. WARNING: This does not recalculate historical average costs and may affect profit report accuracy.', 'warning')
    db.session.delete(transaction)
    db.session.commit()
    log_audit_event('delete_transaction', 'Transaction', transaction_id, f'Deleted transaction for {pile.sku}.')
    return redirect(url_for('manage_transactions'))

# --- Expense Management Routes ---
@app.route('/expenses')
@login_required
@role_required(['admin', 'manager'])
def manage_expenses():
    page = request.args.get('page', 1, type=int)
    expenses_query = Expense.query.options(joinedload(Expense.category)).order_by(Expense.expense_date.desc())
    pagination = expenses_query.paginate(page=page, per_page=10, error_out=False)
    categories = ExpenseCategory.query.order_by(ExpenseCategory.name).all()
    return render_template('expenses.html', expenses=pagination.items, pagination=pagination, categories=categories)

@app.route('/expenses/add', methods=['POST'])
@login_required
@role_required(['admin', 'manager'])
def add_expense():
    description = request.form.get('description')
    amount = float(request.form.get('amount', 0))
    expense_date_str = request.form.get('expense_date')
    category_id = int(request.form.get('category_id'))
    try:
        expense_date = datetime.strptime(expense_date_str, '%Y-%m-%d')
    except (ValueError, TypeError):
        expense_date = datetime.now()
    if not description or amount <= 0 or not category_id:
        flash('Invalid expense data provided.', 'error')
        return redirect(url_for('manage_expenses'))
    new_expense = Expense(description=description, amount=amount, expense_date=expense_date, category_id=category_id, user_id=current_user.id)
    db.session.add(new_expense)
    db.session.commit()
    log_audit_event('add_expense', 'Expense', new_expense.id, f'Added expense: {description} for ${amount}')
    flash('Expense added successfully.', 'success')
    return redirect(url_for('manage_expenses'))

@app.route('/expenses/delete/<int:expense_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    db.session.delete(expense)
    db.session.commit()
    log_audit_event('delete_expense', 'Expense', expense_id, f'Deleted expense: {expense.description}')
    flash('Expense deleted successfully.', 'success')
    return redirect(url_for('manage_expenses'))

@app.route('/expense_categories', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_expense_categories():
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            existing_category = ExpenseCategory.query.filter_by(name=name).first()
            if not existing_category:
                new_category = ExpenseCategory(name=name)
                db.session.add(new_category)
                db.session.commit()
                flash('Expense category added successfully.', 'success')
            else:
                flash('Category name already exists.', 'error')
        else:
            flash('Category name cannot be empty.', 'error')
        return redirect(url_for('manage_expense_categories'))
    categories = ExpenseCategory.query.order_by(ExpenseCategory.name).all()
    return render_template('expense_categories.html', categories=categories)

@app.route('/expense_categories/delete/<int:category_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_expense_category(category_id):
    category = ExpenseCategory.query.get_or_404(category_id)
    if category.expenses:
        flash('Cannot delete category with associated expenses.', 'error')
        return redirect(url_for('manage_expense_categories'))
    db.session.delete(category)
    db.session.commit()
    flash('Expense category deleted successfully.', 'success')
    return redirect(url_for('manage_expense_categories'))
    
# --- Reports Route ---
@app.route('/reports')
@login_required
@role_required(['admin', 'manager'])
def reports():
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    today = datetime.today()
    if not start_date_str:
        start_date = today.replace(day=1)
    else:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
    if not end_date_str:
        end_date = today
    else:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
    end_date_inclusive = end_date + timedelta(days=1)

    sold_transactions = Transaction.query.filter_by(transaction_type='out').filter(Transaction.transaction_date >= start_date, Transaction.transaction_date < end_date_inclusive).order_by(Transaction.transaction_date.desc()).all()
    received_transactions = Transaction.query.filter_by(transaction_type='in').filter(Transaction.transaction_date >= start_date, Transaction.transaction_date < end_date_inclusive).order_by(Transaction.transaction_date.desc()).all()
    all_transactions = Transaction.query.filter(Transaction.transaction_date >= start_date, Transaction.transaction_date < end_date_inclusive).order_by(Transaction.transaction_date.desc()).all()
    expenses = Expense.query.options(joinedload(Expense.category)).filter(Expense.expense_date >= start_date, Expense.expense_date < end_date_inclusive).order_by(Expense.expense_date.desc()).all()
    
    total_sales_value = db.session.query(func.sum(Transaction.total_value)).filter(Transaction.transaction_type == 'out', Transaction.transaction_date >= start_date, Transaction.transaction_date < end_date_inclusive).scalar() or 0.0
    total_cost_of_goods_sold = db.session.query(func.sum(Transaction.cost_of_goods_sold)).filter(Transaction.transaction_type == 'out', Transaction.transaction_date >= start_date, Transaction.transaction_date < end_date_inclusive).scalar() or 0.0
    total_expenses = db.session.query(func.sum(Expense.amount)).filter(Expense.expense_date >= start_date, Expense.expense_date < end_date_inclusive).scalar() or 0.0
    gross_profit = total_sales_value - total_cost_of_goods_sold
    net_profit = gross_profit - total_expenses

    expenses_by_category = db.session.query(ExpenseCategory.name, func.sum(Expense.amount)).join(Expense).filter(Expense.expense_date >= start_date, Expense.expense_date < end_date_inclusive).group_by(ExpenseCategory.name).all()
    expense_chart_data = {'labels': [e[0] for e in expenses_by_category], 'values': [e[1] for e in expenses_by_category]}
    
    piles_current_stock = Pile.query.order_by(Pile.sku).all()
    low_stock_threshold = g.get('low_stock_threshold', 10)
    low_stock_piles = Pile.query.filter(Pile.current_stock < low_stock_threshold).all()

    return render_template('reports.html', 
                           total_sales_value=total_sales_value, total_cost_of_goods_sold=total_cost_of_goods_sold,
                           gross_profit=gross_profit, total_expenses=total_expenses, net_profit=net_profit,
                           expense_chart_data=json.dumps(expense_chart_data),
                           expenses=expenses,
                           sold_transactions=sold_transactions, received_transactions=received_transactions,
                           all_transactions=all_transactions, piles_current_stock=piles_current_stock,
                           low_stock_piles=low_stock_piles, start_date=start_date.strftime('%Y-%m-%d'),
                           end_date=end_date.strftime('%Y-%m-%d'))

# --- Audit Log Route ---
@app.route('/audit_log')
@login_required
@role_required('admin')
def view_audit_log():
    page = request.args.get('page', 1, type=int)
    log_query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    pagination = log_query.paginate(page=page, per_page=20, error_out=False)
    return render_template('audit_log.html', audit_logs=pagination.items, pagination=pagination)

# --- User Management and Settings Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            log_audit_event('login', 'User', user.id, f'User {user.username} logged in.')
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_audit_event('logout', 'User', current_user.id, f'User {current_user.username} logged out.')
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def register():
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        existing_user = User.query.filter_by(username=request.form['username']).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return render_template('register.html')
        new_user = User(username=request.form['username'], role=request.form['role'])
        new_user.set_password(request.form['password'])
        db.session.add(new_user)
        db.session.commit()
        log_audit_event('register', 'User', new_user.id, f'New user registered: {new_user.username}')
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_new_password:
            flash('New passwords do not match.', 'error')
        else:
            current_user.set_password(new_password)
            db.session.commit()
            log_audit_event('change_password', 'User', current_user.id, 'User changed their password.')
            flash('Your password has been updated successfully.', 'success')
            return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def settings():
    if request.method == 'POST':
        # Handle regular form data
        for key, value in request.form.items():
            setting = Setting.query.filter_by(key=key).first()
            if setting:
                setting.value = value
            else:
                new_setting = Setting(key=key, value=value)
                db.session.add(new_setting)

        # Handle file upload for background image
        if 'background_image' in request.files:
            file = request.files['background_image']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Ensure the upload folder exists
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                # Save filename to database
                bg_setting = Setting.query.filter_by(key='background_image').first()
                if bg_setting:
                    bg_setting.value = filename
                else:
                    new_bg_setting = Setting(key='background_image', value=filename)
                    db.session.add(new_bg_setting)
                
                flash('Background image updated successfully.', 'success')

        db.session.commit()
        log_audit_event('update_settings', 'Application', details='Admin updated application settings.')
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('settings'))

    settings_dict = {s.key: s.value for s in Setting.query.all()}
    return render_template('settings.html', settings=settings_dict)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin_password') 
            db.session.add(admin_user)
            print("Admin user created.")
        if not Setting.query.filter_by(key='low_stock_threshold').first():
            setting = Setting(key='low_stock_threshold', value='10')
            db.session.add(setting)
            print("Default setting 'low_stock_threshold' created.")
        db.session.commit()
    app.run(debug=True)
