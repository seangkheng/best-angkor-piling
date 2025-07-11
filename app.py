# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, flash, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps # Import wraps for decorator

# Initialize Flask application
app = Flask(__name__)

# Configure database
# Use an absolute path for the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'best_angkor_piling.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key_here' # Replace with a strong secret key

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if not authenticated
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "info"

# --- Database Models ---

# User Model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user', nullable=False) # e.g., 'admin', 'manager', 'stock_keeper'
    created_at = db.Column(db.DateTime, default=datetime.now)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Pile Model for inventory items
class Pile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pile_type = db.Column(db.String(100), nullable=False)
    size = db.Column(db.String(100), nullable=False)
    length = db.Column(db.Float, nullable=False)
    sku = db.Column(db.String(100), unique=True, nullable=False)
    current_stock = db.Column(db.Integer, default=0)
    unit_price = db.Column(db.Float, default=0.0) # Current unit price for the pile
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Relationship to transactions
    transactions = db.relationship('Transaction', backref='pile', lazy=True)

    def __repr__(self):
        return f'<Pile {self.sku}>'

# Customer Site Model
class CustomerSite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)

    # Relationship to transactions
    transactions = db.relationship('Transaction', backref='customer_site', lazy=True)

    def __repr__(self):
        return f'<CustomerSite {self.name}>'

# Transaction Model for stock movements
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pile_id = db.Column(db.Integer, db.ForeignKey('pile.id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('customer_site.id'), nullable=True) # Optional site
    transaction_type = db.Column(db.String(50), nullable=False) # 'in' or 'out'
    quantity = db.Column(db.Integer, nullable=False)
    unit_price_at_transaction = db.Column(db.Float, nullable=False, default=0.0) # Price at the time of transaction
    total_value = db.Column(db.Float, nullable=False, default=0.0)
    transaction_date = db.Column(db.DateTime, default=datetime.now)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f'<Transaction {self.id} - {self.transaction_type} {self.quantity} of Pile {self.pile_id}>'

# Audit Log Model
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Nullable if action is by system/unauthenticated
    username = db.Column(db.String(80), nullable=True) # Store username directly for historical accuracy
    action = db.Column(db.String(100), nullable=False) # e.g., 'add_pile', 'edit_transaction', 'login'
    entity_type = db.Column(db.String(100), nullable=True) # e.g., 'Pile', 'Transaction', 'User'
    entity_id = db.Column(db.Integer, nullable=True) # ID of the entity affected
    details = db.Column(db.Text) # More detailed description of the change
    timestamp = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref='audit_logs', lazy=True)

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username} on {self.entity_type}:{self.entity_id} at {self.timestamp}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Context Processor ---
# This makes 'current_year' available in all templates
@app.context_processor
def inject_global_vars():
    return dict(current_year=datetime.now().year)

# --- Before Request Hook ---
# Ensures that the database session is properly managed
@app.before_request
def before_request():
    g.db = db.session

# --- Custom Decorator for Role-Based Access Control ---
def role_required(roles):
    """
    Decorator to restrict access to a route based on user roles.
    `roles` can be a single string or a list of strings.
    Example: @role_required('admin') or @role_required(['admin', 'manager'])
    """
    if not isinstance(roles, list):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "info")
                return redirect(url_for('login', next=request.url))
            if current_user.role not in roles:
                flash("You do not have permission to access this page.", "error")
                return redirect(url_for('index')) # Redirect to dashboard or a permission denied page
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    db.session.rollback() # Rollback any pending transactions
    return render_template('500.html'), 500

# --- Audit Logging Function ---
def log_audit_event(action, entity_type=None, entity_id=None, details=None):
    user_id = current_user.id if current_user.is_authenticated else None
    username = current_user.username if current_user.is_authenticated else 'Guest'
    log_entry = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details
    )
    db.session.add(log_entry)
    db.session.commit()

# --- Routes ---

# Home/Dashboard Route
@app.route('/')
@login_required
def index():
    # Get counts for dashboard cards
    total_piles = Pile.query.count()
    total_sites = CustomerSite.query.count()
    
    # Low stock piles (e.g., stock < 10)
    low_stock_threshold = 10
    low_stock_piles = Pile.query.filter(Pile.current_stock < low_stock_threshold).all()
    
    # Recent transactions (e.g., last 5)
    recent_transactions = Transaction.query.order_by(Transaction.transaction_date.desc()).limit(5).all()

    return render_template('index.html',
                           piles=Pile.query.all(), # Used for total piles count
                           customer_sites=CustomerSite.query.all(), # Used for total sites count
                           low_stock_piles=low_stock_piles,
                           recent_transactions=recent_transactions,
                           low_stock_threshold=low_stock_threshold
                           )

# --- Pile Management Routes ---

@app.route('/piles')
@login_required
@role_required(['admin', 'manager', 'stock_keeper']) # Stock Keeper can view piles
def manage_piles():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'sku')
    order = request.args.get('order', 'asc')

    # Define valid sortable columns
    valid_sort_columns = ['pile_type', 'size', 'length', 'sku', 'current_stock', 'unit_price', 'created_at']

    if sort_by not in valid_sort_columns:
        sort_by = 'sku' # Default sort

    # Get the column to sort by
    sort_column = getattr(Pile, sort_by)
    if order == 'desc':
        piles_query = Pile.query.order_by(sort_column.desc())
    else:
        piles_query = Pile.query.order_by(sort_column.asc())

    pagination = piles_query.paginate(page=page, per_page=10, error_out=False)
    piles = pagination.items
    return render_template('piles.html', piles=piles, pagination=pagination, sort_by=sort_by, order=order)

@app.route('/add_pile', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can add piles
def add_pile():
    if request.method == 'POST':
        pile_type = request.form['pile_type']
        size = request.form['size']
        length = float(request.form['length'])
        sku = request.form['sku']
        unit_price = float(request.form['unit_price'])
        description = request.form.get('description')

        existing_pile = Pile.query.filter_by(sku=sku).first()
        if existing_pile:
            flash('SKU already exists. Please use a unique SKU.', 'error')
            return render_template('add_pile.html')

        new_pile = Pile(pile_type=pile_type, size=size, length=length, sku=sku, unit_price=unit_price, description=description)
        db.session.add(new_pile)
        db.session.commit()
        log_audit_event('add_pile', 'Pile', new_pile.id, f'Added new pile: {new_pile.sku}')
        flash('Pile added successfully!', 'success')
        return redirect(url_for('manage_piles'))
    return render_template('add_pile.html')

@app.route('/edit_pile/<int:pile_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can edit piles
def edit_pile(pile_id):
    pile = Pile.query.get_or_404(pile_id)
    if request.method == 'POST':
        old_data = {
            'pile_type': pile.pile_type,
            'size': pile.size,
            'length': pile.length,
            'sku': pile.sku,
            'unit_price': pile.unit_price,
            'description': pile.description
        }

        pile.pile_type = request.form['pile_type']
        pile.size = request.form['size']
        pile.length = float(request.form['length'])
        pile.sku = request.form['sku']
        pile.unit_price = float(request.form['unit_price'])
        pile.description = request.form.get('description')

        # Check for duplicate SKU if SKU was changed
        if pile.sku != old_data['sku']:
            existing_pile = Pile.query.filter_by(sku=pile.sku).first()
            if existing_pile and existing_pile.id != pile.id:
                flash('SKU already exists. Please use a unique SKU.', 'error')
                return render_template('edit_pile.html', pile=pile)

        db.session.commit()
        
        # Log changes
        changes = []
        for key, value in old_data.items():
            new_value = getattr(pile, key)
            if str(value) != str(new_value): # Convert to string for comparison to handle float precision
                changes.append(f'{key}: {value} -> {new_value}')
        
        if changes:
            log_audit_event('edit_pile', 'Pile', pile.id, f'Updated pile {pile.sku}. Changes: {"; ".join(changes)}')
        else:
            log_audit_event('edit_pile', 'Pile', pile.id, f'Updated pile {pile.sku}. No significant changes.')

        flash('Pile updated successfully!', 'success')
        return redirect(url_for('manage_piles'))
    
    # Get transactions related to this pile for display on the edit page
    transactions = Transaction.query.filter_by(pile_id=pile.id).order_by(Transaction.transaction_date.desc()).all()
    return render_template('edit_piles.html', pile=pile, transactions=transactions)


@app.route('/delete_pile/<int:pile_id>', methods=['POST'])
@login_required
@role_required('admin') # Only Admin can delete piles
def delete_pile(pile_id):
    pile = Pile.query.get_or_404(pile_id)
    sku = pile.sku # Store SKU before deleting for logging

    # Delete associated transactions first to avoid foreign key constraints
    transactions_to_delete = Transaction.query.filter_by(pile_id=pile.id).all()
    for transaction in transactions_to_delete:
        db.session.delete(transaction)
    
    db.session.delete(pile)
    db.session.commit()
    log_audit_event('delete_pile', 'Pile', pile_id, f'Deleted pile: {sku} and all its associated transactions.')
    flash('Pile and all associated transactions deleted successfully!', 'success')
    return redirect(url_for('manage_piles'))

# --- Customer Site Management Routes ---

@app.route('/sites')
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can manage sites
def manage_sites():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'name')
    order = request.args.get('order', 'asc')

    valid_sort_columns = ['name', 'address', 'phone', 'created_at']
    if sort_by not in valid_sort_columns:
        sort_by = 'name'

    sort_column = getattr(CustomerSite, sort_by)
    if order == 'desc':
        sites_query = CustomerSite.query.order_by(sort_column.desc())
    else:
        sites_query = CustomerSite.query.order_by(sort_column.asc())

    pagination = sites_query.paginate(page=page, per_page=10, error_out=False)
    customer_sites = pagination.items
    return render_template('customer_sites.html', customer_sites=customer_sites, pagination=pagination, sort_by=sort_by, order=order)

@app.route('/add_customer_site', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can add sites
def add_customer_site():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form.get('address')
        phone = request.form.get('phone')

        existing_site = CustomerSite.query.filter_by(name=name).first()
        if existing_site:
            flash('Customer/Site name already exists. Please use a unique name.', 'error')
            return render_template('add_customer_site.html')

        new_site = CustomerSite(name=name, address=address, phone=phone)
        db.session.add(new_site)
        db.session.commit()
        log_audit_event('add_customer_site', 'CustomerSite', new_site.id, f'Added new customer site: {new_site.name}')
        flash('Customer Site added successfully!', 'success')
        return redirect(url_for('manage_sites'))
    return render_template('add_customer_site.html')

@app.route('/edit_customer_site/<int:site_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can edit sites
def edit_customer_site(site_id):
    site = CustomerSite.query.get_or_404(site_id)
    if request.method == 'POST':
        old_data = {
            'name': site.name,
            'address': site.address,
            'phone': site.phone
        }

        site.name = request.form['name']
        site.address = request.form.get('address')
        site.phone = request.form.get('phone')

        # Check for duplicate name if name was changed
        if site.name != old_data['name']:
            existing_site = CustomerSite.query.filter_by(name=site.name).first()
            if existing_site and existing_site.id != site.id:
                flash('Customer/Site name already exists. Please use a unique name.', 'error')
                return render_template('edit_customer_site.html', site=site)

        db.session.commit()

        changes = []
        for key, value in old_data.items():
            new_value = getattr(site, key)
            if str(value) != str(new_value):
                changes.append(f'{key}: {value} -> {new_value}')
        
        if changes:
            log_audit_event('edit_customer_site', 'CustomerSite', site.id, f'Updated customer site {site.name}. Changes: {"; ".join(changes)}')
        else:
            log_audit_event('edit_customer_site', 'CustomerSite', site.id, f'Updated customer site {site.name}. No significant changes.')

        flash('Customer Site updated successfully!', 'success')
        return redirect(url_for('manage_sites'))
    return render_template('edit_customer_site.html', site=site)

@app.route('/delete_customer_site/<int:site_id>', methods=['POST'])
@login_required
@role_required('admin') # Only Admin can delete sites
def delete_customer_site(site_id):
    site = CustomerSite.query.get_or_404(site_id)
    name = site.name # Store name before deleting for logging

    # Check if there are any transactions associated with this site
    associated_transactions = Transaction.query.filter_by(site_id=site.id).first()
    if associated_transactions:
        flash('Cannot delete customer site because there are associated transactions. Please delete related transactions first.', 'error')
        return redirect(url_for('manage_sites'))

    db.session.delete(site)
    db.session.commit()
    log_audit_event('delete_customer_site', 'CustomerSite', site_id, f'Deleted customer site: {name}')
    flash('Customer Site deleted successfully!', 'success')
    return redirect(url_for('manage_sites'))

# --- Transaction Management Routes ---

@app.route('/transactions')
@login_required
@role_required(['admin', 'manager', 'stock_keeper']) # All roles can view transactions
def manage_transactions():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'transaction_date')
    order = request.args.get('order', 'desc') # Default to descending for date

    search_query = request.args.get('search', '').strip()
    transaction_type_filter = request.args.get('transaction_type_filter', 'all')
    selected_site_id = request.args.get('site_filter', 'all')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Start with a base query and join necessary tables
    transactions_query = Transaction.query.join(Pile) 
    # Only join CustomerSite if a site filter or search query on site name is present
    if selected_site_id != 'all' or search_query:
        transactions_query = transactions_query.outerjoin(CustomerSite) # Use outerjoin to include transactions without a site

    # Apply search filter
    if search_query:
        # Ensure CustomerSite is joined for this part of the filter
        transactions_query = transactions_query.filter(
            (Transaction.notes.ilike(f'%{search_query}%')) |
            (Pile.sku.ilike(f'%{search_query}%')) |
            (CustomerSite.name.ilike(f'%{search_query}%')) # Now CustomerSite is guaranteed to be joined
        )
    
    # Apply transaction type filter
    if transaction_type_filter != 'all':
        transactions_query = transactions_query.filter(Transaction.transaction_type == transaction_type_filter)

    # Apply site filter
    if selected_site_id != 'all':
        transactions_query = transactions_query.filter(Transaction.site_id == int(selected_site_id))
    
    # Apply date range filter
    start_date = None
    end_date = None
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            transactions_query = transactions_query.filter(Transaction.transaction_date >= start_date)
        except ValueError:
            flash('Invalid start date format. Please use YYYY-MM-DD.', 'error')
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1) - timedelta(microseconds=1) # End of day
            transactions_query = transactions_query.filter(Transaction.transaction_date <= end_date)
        except ValueError:
            flash('Invalid end date format. Please use YYYY-MM-DD.', 'error')

    # Define valid sortable columns for transactions
    valid_sort_columns = ['transaction_date', 'pile_id', 'transaction_type', 'quantity', 'unit_price_at_transaction', 'site_id', 'total_value', 'notes']

    if sort_by not in valid_sort_columns:
        sort_by = 'transaction_date' # Default sort

    # Get the column to sort by
    sort_column = getattr(Transaction, sort_by)
    if order == 'desc':
        transactions_query = transactions_query.order_by(sort_column.desc())
    else:
        transactions_query = transactions_query.order_by(sort_column.asc())

    pagination = transactions_query.paginate(page=page, per_page=10, error_out=False)
    transactions = pagination.items
    
    customer_sites = CustomerSite.query.all() # For the filter dropdown

    return render_template('transactions.html', 
                           transactions=transactions, 
                           pagination=pagination, 
                           sort_by=sort_by, 
                           order=order,
                           search_query=search_query,
                           selected_transaction_type=transaction_type_filter,
                           customer_sites=customer_sites,
                           selected_site_id=selected_site_id,
                           start_date=start_date_str,
                           end_date=end_date_str)


@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'stock_keeper']) # All roles can add transactions
def add_transaction():
    piles = Pile.query.all()
    customer_sites = CustomerSite.query.all()

    if request.method == 'POST':
        pile_id = request.form['pile_id']
        site_id = request.form.get('site_id')
        transaction_type = request.form['transaction_type']
        quantity = int(request.form['quantity'])
        unit_price_at_transaction = float(request.form['unit_price_at_transaction'])
        notes = request.form.get('notes')

        pile = Pile.query.get_or_404(pile_id)
        
        # Calculate total value
        total_value = unit_price_at_transaction * quantity

        # Update stock based on transaction type
        if transaction_type == 'in':
            pile.current_stock += quantity
            action_details = f'Received {quantity} of {pile.sku} at ${unit_price_at_transaction:.2f} each. Total: ${total_value:.2f}'
            flash_message = f'New IN transaction: {quantity} of {pile.sku} received. Total value: ${total_value:.2f}.'
            flash_category = 'info'
        elif transaction_type == 'out':
            if pile.current_stock < quantity:
                flash(f'Not enough stock for {pile.sku}. Current stock: {pile.current_stock}', 'error')
                return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites)
            pile.current_stock -= quantity
            action_details = f'Sold {quantity} of {pile.sku} at ${unit_price_at_transaction:.2f} each. Total: ${total_value:.2f}'
            flash_message = f'New OUT transaction: {quantity} of {pile.sku} sold. Total value: ${total_value:.2f}.'
            flash_category = 'warning' # Use warning for sales alerts
        else:
            flash('Invalid transaction type.', 'error')
            return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites)

        new_transaction = Transaction(
            pile_id=pile_id,
            site_id=site_id if site_id != 'None' else None,
            transaction_type=transaction_type,
            quantity=quantity,
            unit_price_at_transaction=unit_price_at_transaction,
            total_value=total_value,
            notes=notes
        )
        db.session.add(new_transaction)
        db.session.commit()
        
        log_audit_event('add_transaction', 'Transaction', new_transaction.id, action_details)
        
        # Flash message for the current user
        flash('Transaction added successfully and stock updated!', 'success')

        # Flash message for managers/admins (transaction alert)
        if current_user.role in ['stock_keeper']: # If stock keeper makes transaction, alert manager/admin
            flash(flash_message, flash_category) # This flash will be visible to the current user, but the idea is it's an alert
        
        return redirect(url_for('manage_transactions'))

    return render_template('add_transaction.html', piles=piles, customer_sites=customer_sites)


@app.route('/edit_transaction/<int:transaction_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'manager', 'stock_keeper']) # All roles can edit transactions
def edit_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    piles = Pile.query.all()
    customer_sites = CustomerSite.query.all()

    if request.method == 'POST':
        old_pile_id = transaction.pile_id
        old_quantity = transaction.quantity
        old_transaction_type = transaction.transaction_type
        old_unit_price = transaction.unit_price_at_transaction
        old_site_id = transaction.site_id

        new_pile_id = request.form['pile_id']
        new_site_id = request.form.get('site_id')
        new_transaction_type = request.form['transaction_type']
        new_quantity = int(request.form['quantity'])
        new_unit_price_at_transaction = float(request.form['unit_price_at_transaction'])
        new_notes = request.form.get('notes')

        # Get the old pile and new pile objects
        old_pile = Pile.query.get(old_pile_id)
        new_pile = Pile.query.get(new_pile_id)

        # Revert old stock change
        if old_transaction_type == 'in':
            old_pile.current_stock -= old_quantity
        elif old_transaction_type == 'out':
            old_pile.current_stock += old_quantity

        # Apply new stock change
        if new_transaction_type == 'in':
            new_pile.current_stock += new_quantity
        elif new_transaction_type == 'out':
            # Check stock for new pile before applying
            if new_pile.current_stock < new_quantity:
                flash(f'Not enough stock for {new_pile.sku}. Current stock: {new_pile.current_stock}', 'error')
                # Revert stock change if validation fails
                if old_transaction_type == 'in':
                    old_pile.current_stock += old_quantity
                elif old_transaction_type == 'out':
                    old_pile.current_stock -= old_quantity
                db.session.rollback() # Rollback any changes
                return render_template('edit_transaction.html', transaction=transaction, piles=piles, customer_sites=customer_sites)
            new_pile.current_stock -= new_quantity

        # Update transaction details
        transaction.pile_id = new_pile_id
        transaction.site_id = new_site_id if new_site_id != 'None' else None
        transaction.transaction_type = new_transaction_type
        transaction.quantity = new_quantity
        transaction.unit_price_at_transaction = new_unit_price_at_transaction
        transaction.total_value = new_unit_price_at_transaction * new_quantity
        transaction.notes = new_notes
        transaction.transaction_date = datetime.now() # Update timestamp on edit

        db.session.commit()
        
        log_audit_event('edit_transaction', 'Transaction', transaction.id, f'Edited transaction {transaction.id}. Stock updated for {old_pile.sku} and {new_pile.sku}.')
        
        # Flash message for the current user
        flash('Transaction updated successfully and stock adjusted!', 'success')

        # Flash message for managers/admins (transaction alert)
        if current_user.role in ['stock_keeper']: # If stock keeper makes transaction, alert manager/admin
            flash(f'Transaction {transaction.id} edited by {current_user.username}.', 'info')
        
        return redirect(url_for('manage_transactions'))

    return render_template('edit_transaction.html', transaction=transaction, piles=piles, customer_sites=customer_sites)


@app.route('/delete_transaction/<int:transaction_id>', methods=['POST'])
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can delete transactions
def delete_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    pile = Pile.query.get(transaction.pile_id)

    # Revert stock change when deleting transaction
    if transaction.transaction_type == 'in':
        pile.current_stock -= transaction.quantity
    elif transaction.transaction_type == 'out':
        pile.current_stock += transaction.quantity

    db.session.delete(transaction)
    db.session.commit()
    log_audit_event('delete_transaction', 'Transaction', transaction_id, f'Deleted transaction {transaction_id}. Stock adjusted for {pile.sku}.')
    flash('Transaction deleted successfully and stock reverted!', 'success')
    
    # Flash message for managers/admins (transaction alert)
    if current_user.role in ['stock_keeper']: # If stock keeper deletes transaction, alert manager/admin
        flash(f'Transaction {transaction_id} deleted by {current_user.username}. Stock adjusted.', 'error') # Use error for deletion alerts
    
    return redirect(url_for('manage_transactions'))

# --- Reports Route ---

@app.route('/reports')
@login_required
@role_required(['admin', 'manager']) # Only Admin and Manager can view reports
def reports():
    # Current Stock Report
    piles_current_stock = Pile.query.order_by(Pile.sku).all()

    # Sold Transactions Report (type 'out')
    sold_transactions = Transaction.query.filter_by(transaction_type='out').order_by(Transaction.transaction_date.desc()).all()

    # Received Transactions Report (type 'in')
    received_transactions = Transaction.query.filter_by(transaction_type='in').order_by(Transaction.transaction_date.desc()).all()

    # All Transactions Report
    all_transactions = Transaction.query.order_by(Transaction.transaction_date.desc()).all()

    # Low Stock Piles Report (same as dashboard)
    low_stock_threshold = 10
    low_stock_piles = Pile.query.filter(Pile.current_stock < low_stock_threshold).all()

    # Profit & Loss Report (Simple Estimation)
    total_sales_value = db.session.query(db.func.sum(Transaction.total_value)).filter_by(transaction_type='out').scalar() or 0.0
    
    # Estimate Cost of Goods Sold (COGS) for 'out' transactions
    # This is a simplified calculation: quantity sold * current unit_price of the pile
    # For a more accurate COGS, you'd need to track the cost of each specific unit received.
    cogs_query = db.session.query(db.func.sum(Transaction.quantity * Pile.unit_price)).join(Pile).filter(Transaction.transaction_type == 'out').scalar()
    total_cost_of_goods_sold = cogs_query or 0.0
    
    total_profit = total_sales_value - total_cost_of_goods_sold

    return render_template('reports.html',
                           piles_current_stock=piles_current_stock,
                           sold_transactions=sold_transactions,
                           received_transactions=received_transactions,
                           all_transactions=all_transactions,
                           low_stock_piles=low_stock_piles,
                           low_stock_threshold=low_stock_threshold,
                           total_sales_value=total_sales_value,
                           total_cost_of_goods_sold=total_cost_of_goods_sold,
                           total_profit=total_profit)

# --- Audit Log Route ---
@app.route('/audit_log')
@login_required
@role_required('admin') # Only Admin can view audit log
def view_audit_log():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'timestamp')
    order = request.args.get('order', 'desc')

    valid_sort_columns = ['timestamp', 'username', 'action', 'entity_type', 'entity_id']
    if sort_by not in valid_sort_columns:
        sort_by = 'timestamp'

    sort_column = getattr(AuditLog, sort_by)
    if order == 'desc':
        audit_logs_query = AuditLog.query.order_by(sort_column.desc())
    else:
        audit_logs_query = AuditLog.query.order_by(sort_column.asc())

    pagination = audit_logs_query.paginate(page=page, per_page=20, error_out=False)
    audit_logs = pagination.items
    return render_template('audit_log.html', audit_logs=audit_logs, pagination=pagination, sort_by=sort_by, order=order)

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            log_audit_event('login', 'User', user.id, f'User {user.username} logged in.')
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@role_required('admin') # Only Admin can register new users
def register():
    if current_user.is_authenticated and current_user.role != 'admin':
        flash("You do not have permission to register new users.", "error")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'stock_keeper') # Default role for new users

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        log_audit_event('register', 'User', new_user.id, f'New user registered: {new_user.username} with role {new_user.role}')
        flash(f'Registration successful for {new_user.username} with role {new_user.role}!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    log_audit_event('logout', 'User', current_user.id, f'User {current_user.username} logged out.')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Database Initialization (Run this once to create the database) ---
# To run this, you can open a Python interpreter in your project directory
# and execute:
# from app import app, db
# with app.app_context():
#     db.create_all()
#     # Optional: Create an admin user
#     if not User.query.filter_by(username='admin').first():
#         admin_user = User(username='admin', role='admin')
#         admin_user.set_password('admin_password') # Change this password!
#         db.session.add(admin_user)
#         db.session.commit()
#         print("Admin user created: username='admin', password='admin_password'")
#     else:
#         print("Admin user already exists.")

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        # Optional: Create an admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', role='admin')
            admin_user.set_password('admin_password') # IMPORTANT: Change this password in production!
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created: username='admin', password='admin_password'")
        else:
            print("Admin user already exists.")
    
    app.run(debug=True) # Run in debug mode for development
