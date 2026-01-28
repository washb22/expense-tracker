import os
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import json
import re
import uuid
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

def get_kst_now():
    return datetime.utcnow() + timedelta(hours=9)
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import io
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def get_database_url():
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        return database_url
    if os.path.exists('/var/data/render'):
        db_path = '/var/data/render/tracker.db'
        return f'sqlite:///{db_path}'
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    db_path = os.path.join(instance_path, 'tracker.db')
    return f'sqlite:///{db_path}'

app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def role_required(role="member", menu=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            active_workspace_id = session.get('active_workspace_id')
            if not active_workspace_id:
                flash("먼저 사업장을 선택해주세요.", "error")
                return redirect(url_for('manage_workspaces'))

            membership = WorkspaceMember.query.filter_by(user_id=current_user.id, workspace_id=active_workspace_id).first()
            if not membership:
                flash("현재 사업장에 대한 접근 권한이 없습니다.", "error")
                return redirect(url_for('manage_workspaces'))
            
            roles_hierarchy = {'member': 1, 'admin': 2, 'owner': 3}
            user_level = roles_hierarchy.get(membership.role, 0)
            required_level = roles_hierarchy.get(role, 0)

            # --- ⭐️⭐️⭐️ 여기가 핵심 수정 부분입니다 ⭐️⭐️⭐️ ---
            def get_user_permissions():
                if membership.role in ['owner', 'admin']:
                    return {'dashboard', 'classify', 'rules', 'business_dashboard', 'business_sales', 'business_products', 'manage_workspaces'}
                else:
                    permissions = MenuPermission.query.filter_by(user_id=current_user.id, workspace_id=active_workspace_id).all()
                    return {p.menu_name for p in permissions}

            user_permissions = get_user_permissions()

            # 접근 거부 시, 사용자가 갈 수 있는 첫 페이지로 리디렉션
            def redirect_to_fallback():
                flash("이 페이지에 접근할 권한이 없습니다.", "error")
                # 권한이 있는 페이지 리스트를 순서대로 확인
                fallback_pages = ['business_dashboard', 'business_sales', 'dashboard', 'classify', 'manage_workspaces']
                for page in fallback_pages:
                    if page in user_permissions:
                        # 페이지 이름에 맞는 함수(url)로 리디렉션합니다.
                        # 'show_results'는 'classify' 페이지의 함수 이름입니다.
                        if page == 'classify':
                            return redirect(url_for('show_results'))
                        return redirect(url_for(page))
                # 어떤 페이지 권한도 없다면 사업장 관리 페이지로
                return redirect(url_for('manage_workspaces'))

            if user_level < required_level:
                return redirect_to_fallback()

            if menu and menu not in user_permissions:
                return redirect_to_fallback()
            # --- ⭐️⭐️⭐️ 수정 끝 ⭐️⭐️⭐️ ---

            kwargs['membership'] = membership
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ❗️❗️❗️ [끝] 여기까지 교체하시면 됩니다 ❗️❗️❗️

oauth = OAuth(app)
oauth.register(name='google', client_id=app.config['GOOGLE_CLIENT_ID'], client_secret=app.config['GOOGLE_CLIENT_SECRET'], server_metadata_url='https://accounts.google.com/.well-known/openid-configuration', client_kwargs={'scope': 'openid email profile'})

# --- Database Models ---
class WorkspaceMember(db.Model):
    __tablename__ = 'workspace_member'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), primary_key=True)
    role = db.Column(db.String(50), nullable=False, default='member')
    user = db.relationship('User', back_populates='workspaces')
    workspace = db.relationship('Workspace', back_populates='members')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=get_kst_now)
    last_login = db.Column(db.DateTime)
    workspaces = db.relationship('WorkspaceMember', back_populates='user', cascade="all, delete-orphan")
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Workspace(db.Model):
    __tablename__ = 'workspace'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    members = db.relationship('WorkspaceMember', back_populates='workspace', cascade="all, delete-orphan")
    transactions = db.relationship('Transaction', backref='workspace', lazy=True, cascade="all, delete-orphan")
    rules = db.relationship('Rule', backref='workspace', lazy=True, cascade="all, delete-orphan")
    products = db.relationship('Product', backref='workspace', lazy=True, cascade="all, delete-orphan")
    platforms = db.relationship('Platform', backref='workspace', lazy=True, cascade="all, delete-orphan")
    sales = db.relationship('Sale', backref='workspace', lazy=True, cascade="all, delete-orphan")

class MenuPermission(db.Model):
    __tablename__ = 'menu_permission'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    menu_name = db.Column(db.String(100), nullable=False)
    user = db.relationship('User')
    

class Transaction(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    date = db.Column(db.DateTime, nullable=False)
    merchant = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False, default='미분류')
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    sku = db.Column(db.String(100))
    cost_price = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100))
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Platform(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    commission_rate = db.Column(db.Float, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Sale(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    date = db.Column(db.DateTime, nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    platform_id = db.Column(db.Integer, db.ForeignKey('platform.id'), nullable=False)
    selling_price = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    total_selling_amount = db.Column(db.Integer, nullable=False)
    total_cost_amount = db.Column(db.Integer, nullable=False)
    commission_amount = db.Column(db.Integer, nullable=False)
    net_profit = db.Column(db.Integer, nullable=False)
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', backref='sales')
    platform = db.relationship('Platform', backref='sales')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ❗️❗️❗️ 기존 inject_workspaces 함수를 아래 코드로 통째로 교체해주세요.
@app.context_processor
def inject_workspaces():
    if current_user.is_authenticated:
        # 현재 유저가 소속된 모든 멤버십 정보를 가져옵니다.
        all_memberships = WorkspaceMember.query.filter_by(user_id=current_user.id).all()
        
        active_workspace_id = session.get('active_workspace_id')
        active_workspace = None
        active_membership = None
        user_menu_permissions = set()

        if active_workspace_id:
            active_workspace = Workspace.query.get(active_workspace_id)
            # 활성화된 멤버십 정보를 찾습니다.
            active_membership = next((m for m in all_memberships if m.workspace_id == active_workspace_id), None)

        # 활성화된 멤버십이 있을 경우에만 권한을 계산합니다.
        if active_membership:
            if active_membership.role in ['owner', 'admin']:
                user_menu_permissions = {'dashboard', 'classify', 'rules', 'business_dashboard', 'business_sales', 'business_products', 'manage_workspaces'}
            else:
                permissions = MenuPermission.query.filter_by(user_id=current_user.id, workspace_id=active_workspace_id).all()
                user_menu_permissions = {p.menu_name for p in permissions}

        return dict(
            # 템플릿에는 모든 멤버십 정보를 보내 사이드바 드롭다운을 채웁니다.
            workspace_members=all_memberships,
            active_workspace=active_workspace,
            active_membership=active_membership,
            user_menu_permissions=user_menu_permissions
        )
        
    return dict(workspace_members=[], active_workspace=None, active_membership=None, user_menu_permissions=set())

def clean_merchant_name(name):
    name_lower = str(name).lower()
    if 'facebk' in name_lower or 'facebook' in name_lower: return 'FACEBOOK'
    if 'google' in name_lower or '구글' in name_lower: return 'Google'
    return name

def apply_category(df, workspace_id):
    rules = Rule.query.filter_by(workspace_id=workspace_id).all()
    df_copy = df.copy()
    column_mapping = {'거래일시': '날짜', '거래일자': '날짜', '사용일': '날짜', '거래처': '거래처명', '거래내용': '거래처명', '내용': '거래처명', '가맹점명': '거래처명', '출금액': '금액', '사용금액': '금액', '거래금액': '금액'}
    df_copy.rename(columns=column_mapping, inplace=True, errors='ignore')
    required_columns = ['날짜', '거래처명', '금액']
    if not all(col in df_copy.columns for col in required_columns):
        missing = [col for col in required_columns if col not in df_copy.columns]
        flash(f'엑셀 파일에 필요한 열이 없습니다: {", ".join(missing)}.', 'error')
        return None
    if df_copy['금액'].dtype == 'object':
        df_copy['금액'] = pd.to_numeric(df_copy['금액'].astype(str).str.replace(',', ''), errors='coerce')
    df_copy['날짜'] = pd.to_datetime(df_copy['날짜'], errors='coerce')
    df_copy.dropna(subset=['날짜', '금액'], inplace=True)
    df_copy['금액'] = df_copy['금액'].astype(int)
    def find_category(description):
        desc_processed = re.sub(r'\(주\)|（주）|\(유\)|（유）|[(){}\[\].,]', '', str(description).lower()).strip()
        for rule in rules:
            if rule.keyword.lower().strip() in desc_processed: return rule.category
        return '미분류'
    df_copy['카테고리'] = df_copy['거래처명'].apply(find_category)
    return df_copy

# === Routes ===
@app.route('/')
@login_required
@role_required(menu='dashboard')
def index(membership):
    workspace_id = membership.workspace_id
    transactions = Transaction.query.filter_by(workspace_id=workspace_id).all()
    if not transactions:
        return render_template('index.html', active_page='dashboard', category_totals={}, total_expense=0, available_months=[], selected_month=None, start_date=None, end_date=None, category_details={})
    trans_data = [{'날짜': t.date, '거래처명': t.merchant, '금액': t.amount, '카테고리': t.category} for t in transactions]
    df = pd.DataFrame(trans_data)
    df['날짜'] = pd.to_datetime(df['날짜'], errors='coerce')
    df.dropna(subset=['날짜'], inplace=True)
    df['월'] = df['날짜'].dt.strftime('%Y-%m')
    available_months = sorted(df['월'].unique().tolist(), reverse=True)
    selected_month = request.args.get('month')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    df_filtered = df.copy()
    if start_date and end_date:
        start_date_dt = pd.to_datetime(start_date)
        end_date_dt = pd.to_datetime(end_date)
        df_filtered = df[(df['날짜'] >= start_date_dt) & (df['날짜'] <= end_date_dt)].copy()
        selected_month = None
    elif selected_month in available_months:
        df_filtered = df[df['월'] == selected_month].copy()
    elif not selected_month and not start_date and not end_date and available_months:
        selected_month = available_months[0]
        df_filtered = df[df['월'] == selected_month].copy()
    df_classified = df_filtered[df_filtered['카테고리'] != '미분류']
    total_expense = int(df_classified['금액'].sum()) if not df_classified.empty else 0
    category_totals_series = df_classified.groupby('카테고리')['금액'].sum()
    category_totals = {k: int(v) for k, v in category_totals_series.items()}
    category_details = {}
    for category, group_df in df_classified.groupby('카테고리'):
        group_df_copy = group_df.copy()
        group_df_copy['거래처명_정리'] = group_df_copy['거래처명'].apply(clean_merchant_name)
        merchant_details = {}
        for merchant, trans_df in group_df_copy.groupby('거래처명_정리'):
            total = int(trans_df['금액'].sum())
            trans_df_copy = trans_df.copy()
            trans_df_copy['날짜'] = trans_df_copy['날짜'].dt.strftime('%Y-%m-%d')
            trans = trans_df_copy[['날짜', '거래처명', '금액']].sort_values('날짜', ascending=False).to_dict('records')
            for t in trans: t['금액'] = int(t['금액'])
            merchant_details[merchant] = {'total': total, 'transactions': trans}
        category_details[category] = dict(sorted(merchant_details.items(), key=lambda item: item[1]['total'], reverse=True))
    return render_template('index.html', active_page='dashboard', category_totals=category_totals, total_expense=total_expense, available_months=available_months, selected_month=selected_month, start_date=request.args.get('start_date', ''), end_date=request.args.get('end_date', ''), category_details=category_details)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user is None or not user.check_password(request.form.get('password')):
            flash('사용자 이름 또는 비밀번호가 올바르지 않습니다.', 'error')
            return redirect(url_for('login'))
        login_user(user)
        user.last_login = get_kst_now()
        db.session.commit()
        first_workspace_member = WorkspaceMember.query.filter_by(user_id=user.id).first()
        if first_workspace_member: session['active_workspace_id'] = first_workspace_member.workspace_id
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        if User.query.filter_by(username=request.form.get('username')).first() or User.query.filter_by(email=request.form.get('email')).first():
            flash('이미 존재하는 사용자 이름 또는 이메일입니다.', 'error')
            return redirect(url_for('register'))
        new_user = User(username=request.form.get('username'), email=request.form.get('email'))
        new_user.set_password(request.form.get('password'))
        db.session.add(new_user)
        db.session.commit()
        default_workspace = Workspace(name=f"{new_user.username}의 사업장")
        db.session.add(default_workspace)
        db.session.commit()
        member = WorkspaceMember(user_id=new_user.id, workspace_id=default_workspace.id, role='owner')
        db.session.add(member)
        db.session.commit()
        flash('회원가입이 완료되었습니다! 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    session.pop('active_workspace_id', None)
    return redirect(url_for('login'))

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.userinfo()
    if user_info:
        user = User.query.filter_by(email=user_info['email']).first()
        if user is None:
            user = User(email=user_info['email'], username=user_info.get('name', user_info['email']))
            db.session.add(user)
            db.session.commit()
            default_workspace = Workspace(name=f"{user.username}의 사업장")
            db.session.add(default_workspace)
            db.session.commit()
            member = WorkspaceMember(user_id=user.id, workspace_id=default_workspace.id, role='owner')
            db.session.add(member)
            db.session.commit()
        login_user(user)
        user.last_login = get_kst_now()
        db.session.commit()
        first_workspace_member = WorkspaceMember.query.filter_by(user_id=user.id).first()
        if first_workspace_member: session['active_workspace_id'] = first_workspace_member.workspace_id
        return redirect(url_for('index'))
    flash('Google 로그인에 실패했습니다. 다시 시도해주세요.', 'error')
    return redirect(url_for('login'))

@app.route('/workspace', methods=['GET', 'POST'])
@login_required
def manage_workspaces():
    if request.method == 'POST':
        workspace_name = request.form.get('workspace_name')
        if workspace_name:
            new_workspace = Workspace(name=workspace_name)
            db.session.add(new_workspace)
            db.session.flush()
            member = WorkspaceMember(user_id=current_user.id, workspace_id=new_workspace.id, role='owner')
            db.session.add(member)
            db.session.commit()
            flash(f"'{workspace_name}' 사업장이 생성되었습니다.", 'success')
            session['active_workspace_id'] = new_workspace.id
        else: flash('사업장 이름을 입력해주세요.', 'error')
        return redirect(url_for('manage_workspaces'))
    return render_template('workspace.html', active_page='workspace')

# ❗️❗️❗️ 기존 select_workspace 함수를 아래 코드로 통째로 교체해주세요.
@app.route('/workspace/select/<int:workspace_id>')
@login_required
def select_workspace(workspace_id):
    # 사용자가 해당 사업장의 멤버인지 확인
    member_check = WorkspaceMember.query.filter_by(user_id=current_user.id, workspace_id=workspace_id).first()
    
    if member_check:
        # 멤버가 맞으면 세션에 활성 사업장 ID를 저장
        session['active_workspace_id'] = workspace_id
    else:
        flash('유효하지 않은 사업장입니다.', 'error')
    
    # --- ⭐️⭐️⭐️ 여기가 핵심 수정 부분입니다 ⭐️⭐️⭐️ ---
    # 이전 페이지로 돌아가는 대신, 항상 메인 대시보드로 이동시킵니다.
    return redirect(url_for('index'))
    # --- ⭐️⭐️⭐️ 수정 끝 ⭐️⭐️⭐️ ---

@app.route('/workspace/delete/<int:workspace_id>', methods=['POST'])
@login_required
def delete_workspace(workspace_id):
    member_check = WorkspaceMember.query.filter_by(user_id=current_user.id, workspace_id=workspace_id, role='owner').first()
    if member_check:
        workspace_to_delete = Workspace.query.get(workspace_id)
        db.session.delete(workspace_to_delete)
        db.session.commit()
        flash(f"'{workspace_to_delete.name}' 사업장과 모든 데이터가 삭제되었습니다.", 'success')
        if session.get('active_workspace_id') == workspace_id: session.pop('active_workspace_id', None)
    else: flash('사업장을 삭제할 권한이 없습니다.', 'error')
    return redirect(url_for('manage_workspaces'))

# ⬇️⬇️⬇️ 이 함수를 새로 추가해주세요 ⬇️⬇️⬇️
@app.route('/workspace/edit/<int:workspace_id>', methods=['POST'])
@login_required
def edit_workspace(workspace_id):
    # 1. 현재 사용자가 해당 사업장의 owner 또는 admin인지 확인
    membership = WorkspaceMember.query.filter_by(
        user_id=current_user.id,
        workspace_id=workspace_id
    ).first()

    if not membership or membership.role not in ['owner', 'admin']:
        flash('사업장 이름을 수정할 권한이 없습니다.', 'error')
        return redirect(url_for('manage_workspaces'))

    # 2. 수정할 사업장 정보 가져오기
    workspace_to_edit = Workspace.query.get_or_404(workspace_id)
    new_name = request.form.get('workspace_name')

    if new_name:
        # 3. 새 이름으로 업데이트하고 저장
        workspace_to_edit.name = new_name
        db.session.commit()
        flash('사업장 이름이 성공적으로 변경되었습니다.', 'success')
    else:
        flash('새 사업장 이름을 입력해주세요.', 'error')
    
    return redirect(url_for('manage_workspaces'))


# ❗️❗️❗️ 기존 manage_members 함수를 아래 코드로 통째로 교체해주세요.
@app.route('/workspace/<int:workspace_id>/members', methods=['GET', 'POST'])
@login_required
def manage_members(workspace_id):
    # 1. URL로 들어온 특정 사업장을 정확히 찾습니다.
    workspace = Workspace.query.get_or_404(workspace_id)
    
    # 2. 현재 로그인한 사용자가 이 사업장의 관리자인지 확인합니다.
    current_user_membership = WorkspaceMember.query.filter_by(
        user_id=current_user.id, 
        workspace_id=workspace.id
    ).first()

    if not current_user_membership or current_user_membership.role not in ['owner', 'admin']:
        flash('멤버를 관리할 권한이 없습니다.', 'error')
        return redirect(url_for('manage_workspaces'))

    # 3. '멤버 초대' 버튼을 눌렀을 때 (POST)
    if request.method == 'POST':
        email = request.form.get('email')
        role = request.form.get('role')
        user_to_invite = User.query.filter_by(email=email).first()

        if not user_to_invite:
            flash(f"'{email}' 이메일을 가진 사용자를 찾을 수 없습니다. 먼저 회원가입을 해야 합니다.", 'error')
            return redirect(url_for('manage_members', workspace_id=workspace_id))
        
        existing_member = WorkspaceMember.query.filter_by(
            user_id=user_to_invite.id, 
            workspace_id=workspace.id
        ).first()

        if existing_member:
            flash(f"'{user_to_invite.username}'님은 이미 이 사업장의 멤버입니다.", 'warning')
        else:
            new_member = WorkspaceMember(
                user_id=user_to_invite.id, 
                workspace_id=workspace.id,
                role=role
            )
            db.session.add(new_member)
            db.session.commit()
            flash(f"'{user_to_invite.username}'님을 '{role}' 역할로 초대했습니다.", 'success')
            
        return redirect(url_for('manage_members', workspace_id=workspace_id))

    # --- ⭐️⭐️⭐️ 여기가 핵심 수정 부분입니다 ⭐️⭐️⭐️ ---
    # 4. (GET) 페이지를 보여줄 때, DB에 직접 물어서 '이 사업장'의 멤버만 정확히 가져옵니다.
    members = WorkspaceMember.query.filter_by(workspace_id=workspace.id).all()
    # --- ⭐️⭐️⭐️ 수정 끝 ⭐️⭐️⭐️ ---
    
    return render_template('members.html', 
                           workspace=workspace, 
                           members=members, 
                           current_user_role=current_user_membership.role)

@app.route('/workspace/<int:workspace_id>/members/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_member(workspace_id, user_id):
    owner_check = WorkspaceMember.query.filter_by(user_id=current_user.id, workspace_id=workspace_id, role='owner').first()
    if not owner_check:
        flash('멤버를 삭제할 권한이 없습니다.', 'error')
        return redirect(url_for('manage_members', workspace_id=workspace_id))
    if current_user.id == user_id:
        flash('사업장 소유자는 자신을 삭제할 수 없습니다.', 'error')
        return redirect(url_for('manage_members', workspace_id=workspace_id))
    member_to_delete = WorkspaceMember.query.filter_by(user_id=user_id, workspace_id=workspace_id).first()
    if member_to_delete:
        user_info = User.query.get(user_id)
        db.session.delete(member_to_delete)
        db.session.commit()
        flash(f"'{user_info.username}'님을 사업장에서 제외했습니다.", 'success')
    else: flash('삭제할 멤버를 찾을 수 없습니다.', 'error')
    return redirect(url_for('manage_members', workspace_id=workspace_id))

@app.route('/workspace/<int:workspace_id>/permissions/<int:user_id>', methods=['GET', 'POST'])
@login_required
def manage_permissions(workspace_id, user_id):
    AVAILABLE_MENUS = {'dashboard': '대시보드 (지출)', 'classify': '거래내역 분류', 'rules': '카테고리 설정', 'business_dashboard': '사업 대시보드', 'business_sales': '매출 관리', 'business_products': '제품 관리'}
    workspace = Workspace.query.get_or_404(workspace_id)
    member = User.query.get_or_404(user_id)
    current_user_membership = WorkspaceMember.query.filter_by(user_id=current_user.id, workspace_id=workspace.id).first()
    if not current_user_membership or current_user_membership.role not in ['owner', 'admin']:
        flash('멤버 권한을 설정할 권한이 없습니다.', 'error')
        return redirect(url_for('manage_members', workspace_id=workspace_id))
    if request.method == 'POST':
        MenuPermission.query.filter_by(user_id=user_id, workspace_id=workspace_id).delete()
        selected_menus = request.form.getlist('menu_permissions')
        for menu in selected_menus:
            if menu in AVAILABLE_MENUS:
                permission = MenuPermission(user_id=user_id, workspace_id=workspace_id, menu_name=menu)
                db.session.add(permission)
        db.session.commit()
        flash(f"'{member.username}'님의 메뉴 권한이 저장되었습니다.", 'success')
        return redirect(url_for('manage_members', workspace_id=workspace_id))
    user_permissions = {p.menu_name for p in MenuPermission.query.filter_by(user_id=user_id, workspace_id=workspace_id).all()}
    return render_template('permissions.html', workspace=workspace, member=member, available_menus=AVAILABLE_MENUS, user_permissions=user_permissions)

@app.route('/classify', methods=['GET', 'POST'])
@login_required
@role_required(menu='classify')
def show_results(membership):
    workspace_id = membership.workspace_id
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(url_for('show_results'))
        try:
            df_new = pd.read_csv(file) if file.filename.endswith('.csv') else pd.read_excel(file, engine='openpyxl')
            classified_df = apply_category(df_new, workspace_id)
            if classified_df is None: return redirect(url_for('show_results'))
            if request.form.get('action', 'append') == 'upload':
                Transaction.query.filter_by(workspace_id=workspace_id).delete()
                flash('기존 데이터가 모두 삭제되었습니다.', 'info')
            for _, row in classified_df.iterrows():
                transaction = Transaction(date=row['날짜'], merchant=row['거래처명'], amount=row['금액'], category=row['카테고리'], workspace_id=workspace_id)
                db.session.add(transaction)
            db.session.commit()
            flash(f'{len(classified_df)}개의 새 데이터가 추가되었습니다!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'파일 처리 중 오류 발생: {str(e)}', 'error')
        return redirect(url_for('show_results'))
    base_query = Transaction.query.filter_by(workspace_id=workspace_id)
    all_transactions = base_query.all()
    if not all_transactions:
        return render_template('classify.html', active_page='classify', records=[], unique_categories=[], available_months=[])
    all_dates = [t.date for t in all_transactions]
    available_months = sorted({d.strftime('%Y-%m') for d in all_dates}, reverse=True)
    unique_categories = sorted(list({t.category for t in all_transactions}))
    month_filter = request.args.get('month_filter')
    category_filter = request.args.get('category_filter')
    query_filtered = base_query
    if month_filter:
        start_date = datetime.strptime(month_filter, '%Y-%m')
        end_date = start_date.replace(day=1, month=start_date.month % 12 + 1, year=start_date.year + start_date.month // 12)
        query_filtered = query_filtered.filter(Transaction.date >= start_date, Transaction.date < end_date)
    if category_filter:
        query_filtered = query_filtered.filter_by(category=category_filter)
    transactions = query_filtered.order_by(Transaction.date.asc()).all()
    records = [{'id': t.id, '날짜': t.date.strftime('%Y-%m-%d'), '거래처명': t.merchant, '금액': t.amount, '카테고리': t.category} for t in transactions]
    return render_template('classify.html', active_page='classify', records=records, unique_categories=unique_categories, available_months=available_months, selected_month=month_filter, active_filter=category_filter)

# ... (the rest of the file remains the same but with role_required(menu='...') added to each route)
# ... I will now add the remaining routes with the decorator applied ...

@app.route('/rules', methods=['GET', 'POST'])
@login_required
@role_required(menu='rules')
def manage_rules(membership):
    workspace_id = membership.workspace_id
    if request.method == 'POST':
        keyword, category = request.form.get('keyword'), request.form.get('category')
        if keyword and category:
            db.session.add(Rule(keyword=keyword, category=category, workspace_id=workspace_id))
            db.session.commit()
            flash('새 규칙이 추가되었습니다.', 'success')
        else: flash('키워드와 카테고리를 모두 입력해주세요.', 'error')
        return redirect(url_for('manage_rules'))
    rules = Rule.query.filter_by(workspace_id=workspace_id).all()
    return render_template('rules.html', active_page='rules', rules=rules)

@app.route('/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
@role_required(menu='rules')
def delete_rule(rule_id, membership):
    rule_to_delete = Rule.query.get(rule_id)
    if rule_to_delete and rule_to_delete.workspace_id == membership.workspace_id:
        db.session.delete(rule_to_delete)
        db.session.commit()
        flash('규칙이 삭제되었습니다.', 'success')
    else: flash('삭제할 규칙을 찾을 수 없거나 권한이 없습니다.', 'error')
    return redirect(url_for('manage_rules'))

@app.route('/reclassify_all', methods=['POST'])
@login_required
@role_required(menu='rules')
def reclassify_all_data(membership):
    workspace_id = membership.workspace_id
    transactions = Transaction.query.filter_by(workspace_id=workspace_id).all()
    if not transactions:
        flash('재분류할 데이터가 없습니다.', 'info')
        return redirect(url_for('manage_rules'))
    trans_data = [{'날짜': t.date, '거래처명': t.merchant, '금액': t.amount, 'id': t.id} for t in transactions]
    df = pd.DataFrame(trans_data)
    reclassified_df = apply_category(df, workspace_id)
    if reclassified_df is not None:
        for _, row in reclassified_df.iterrows():
            trans_to_update = Transaction.query.get(row['id'])
            if trans_to_update: trans_to_update.category = row['카테고리']
        db.session.commit()
        flash('모든 데이터가 현재 규칙으로 다시 분류되었습니다!', 'success')
    else: flash('데이터 재분류 중 오류가 발생했습니다.', 'error')
    return redirect(url_for('manage_rules'))

@app.route('/delete_item/<item_id>', methods=['POST'])
@login_required
@role_required(menu='classify')
def delete_item(item_id, membership):
    item_to_delete = Transaction.query.get(item_id)
    if item_to_delete and item_to_delete.workspace_id == membership.workspace_id:
        db.session.delete(item_to_delete)
        db.session.commit()
        flash('항목이 삭제되었습니다.', 'success')
    else: flash('삭제할 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
    redirect_args = {k:v for k,v in request.form.items() if k.endswith('_filter')}
    return redirect(url_for('show_results', **redirect_args))

@app.route('/delete_multiple', methods=['POST'])
@login_required
@role_required(menu='classify')
def delete_multiple(membership):
    ids_to_delete = request.get_json().get('ids', [])
    query = Transaction.query.filter(Transaction.id.in_(ids_to_delete), Transaction.workspace_id == membership.workspace_id)
    deleted_count = query.delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'success': True, 'message': f'{deleted_count}개 항목이 삭제되었습니다.'})

@app.route('/edit_transaction/<item_id>', methods=['POST'])
@login_required
@role_required(menu='classify')
def edit_transaction(item_id, membership):
    item_to_edit = Transaction.query.get(item_id)
    if item_to_edit and item_to_edit.workspace_id == membership.workspace_id:
        try:
            item_to_edit.date = datetime.strptime(request.form.get('date'), '%Y-%m-%d')
            item_to_edit.merchant = request.form.get('merchant')
            item_to_edit.amount = int(request.form.get('amount'))
            item_to_edit.category = request.form.get('category')
            db.session.commit()
            flash('거래내역이 성공적으로 수정되었습니다.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'수정 중 오류가 발생했습니다: {e}', 'error')
    else: flash('수정할 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
    redirect_args = {k:v for k,v in request.form.items() if k.endswith('_filter')}
    return redirect(url_for('show_results', **redirect_args))

@app.route('/export')
@login_required
def export_excel():
    workspace_id = session.get('active_workspace_id')
    if not workspace_id:
        flash('내보낼 데이터가 없습니다.', 'error')
        return redirect(url_for('index'))
    transactions = Transaction.query.filter_by(workspace_id=workspace_id).all()
    if not transactions:
        flash('내보낼 거래 내역이 없습니다.', 'info')
        return redirect(url_for('index'))
    trans_data = [{'날짜': t.date, '거래처명': t.merchant, '금액': t.amount, '카테고리': t.category} for t in transactions]
    df = pd.DataFrame(trans_data)
    df['날짜'] = pd.to_datetime(df['날짜'], errors='coerce')
    df.dropna(subset=['날짜'], inplace=True)
    df['월'] = df['날짜'].dt.strftime('%Y-%m')
    selected_month, start_date, end_date = request.args.get('month'), request.args.get('start_date'), request.args.get('end_date')
    df_filtered = df.copy()
    filename = "expense_report"
    if start_date and end_date:
        df_filtered = df[(df['날짜'] >= pd.to_datetime(start_date)) & (df['날짜'] <= pd.to_datetime(end_date))]
        filename += f"_{start_date}_to_{end_date}"
    elif selected_month:
        df_filtered = df[df['월'] == selected_month]
        filename += f"_{selected_month}"
    df_classified = df_filtered[df_filtered['카테고리'] != '미분류'].copy()
    if df_classified.empty:
        flash('선택된 기간에 내보낼 데이터가 없습니다.', 'info')
        return redirect(url_for('index', month=selected_month, start_date=start_date, end_date=end_date))
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        category_totals = df_classified.groupby('카테고리')['금액'].sum().reset_index()
        total_expense = df_classified['금액'].sum()
        summary_df = pd.concat([category_totals, pd.DataFrame([{'카테고리': '총 지출', '금액': total_expense}])], ignore_index=True)
        summary_df.to_excel(writer, sheet_name='요약', index=False)
        for category, group_df in df_classified.groupby('카테고리'):
            group_df.groupby('거래처명')['금액'].sum().reset_index().sort_values(by='금액', ascending=False).to_excel(writer, sheet_name=f'{category} 요약', index=False)
            group_df[['날짜', '거래처명', '금액']].sort_values(by='날짜', ascending=False).to_excel(writer, sheet_name=f'{category} 상세', index=False)
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'{filename}.xlsx')

@app.route('/business/dashboard')
@login_required
@role_required(menu='business_dashboard')
def business_dashboard(membership):
    workspace_id = membership.workspace_id
    all_sales = Sale.query.filter_by(workspace_id=workspace_id).all()
    all_expenses = Transaction.query.filter_by(workspace_id=workspace_id).all()
    # ... (rest of the logic is the same)
    if not all_sales:
        return render_template('business_dashboard.html', active_page='business_dashboard', total_revenue=0, gross_profit=0, total_expenses=0, net_profit=0, recent_sales_data=[], available_months=[], selected_month=None, start_date=None, end_date=None, date_details={})
    sales_df = pd.DataFrame([{'날짜': s.date, '제품명': s.product.name, '판매채널': s.platform.name, '판매가': s.selling_price, '수량': s.quantity, '총매출': s.total_selling_amount, '순이익': s.net_profit, 'id': s.id} for s in all_sales])
    sales_df['날짜'] = pd.to_datetime(sales_df['날짜'])
    sales_df['월'] = sales_df['날짜'].dt.strftime('%Y-%m')
    expense_df = pd.DataFrame([{'날짜': t.date, '금액': t.amount} for t in all_expenses if t.category != '미분류'])
    if not expense_df.empty:
        expense_df['날짜'] = pd.to_datetime(expense_df['날짜'])
        expense_df['월'] = expense_df['날짜'].dt.strftime('%Y-%m')
    available_months = sorted(sales_df['월'].unique().tolist(), reverse=True)
    selected_month, start_date, end_date = request.args.get('month'), request.args.get('start_date'), request.args.get('end_date')
    sales_df_filtered, expense_df_filtered = sales_df.copy(), expense_df.copy()
    if start_date and end_date:
        sales_df_filtered = sales_df[(sales_df['날짜'] >= pd.to_datetime(start_date)) & (sales_df['날짜'] <= pd.to_datetime(end_date))]
        if not expense_df.empty: expense_df_filtered = expense_df[(expense_df['날짜'] >= pd.to_datetime(start_date)) & (expense_df['날짜'] <= pd.to_datetime(end_date))]
        selected_month = None
    elif selected_month in available_months:
        sales_df_filtered = sales_df[sales_df['월'] == selected_month]
        if not expense_df.empty: expense_df_filtered = expense_df[expense_df['월'] == selected_month]
    elif not any([selected_month, start_date, end_date]) and available_months:
        selected_month = available_months[0]
        sales_df_filtered = sales_df[sales_df['월'] == selected_month]
        if not expense_df.empty: expense_df_filtered = expense_df[expense_df['월'] == selected_month]
    total_revenue = int(sales_df_filtered['총매출'].sum())
    gross_profit = int(sales_df_filtered['순이익'].sum())
    total_expenses = int(expense_df_filtered['금액'].sum()) if not expense_df_filtered.empty else 0
    net_profit = gross_profit - total_expenses
    recent_sales_data = sales_df_filtered.nlargest(10, '날짜')
    date_details = {}
    if not sales_df_filtered.empty:
        for date_str, group_df in sales_df_filtered.groupby(sales_df_filtered['날짜'].dt.strftime('%Y-%m-%d')):
            date_summary = {'total_quantity': int(group_df['수량'].sum()), 'total_revenue': int(group_df['총매출'].sum()), 'total_profit': int(group_df['순이익'].sum()), 'products': {}}
            for product_name, product_group in group_df.groupby('제품명'):
                product_summary = {'quantity': int(product_group['수량'].sum()), 'revenue': int(product_group['총매출'].sum()), 'profit': int(product_group['순이익'].sum()), 'sales': []}
                for _, row in product_group.iterrows():
                    product_summary['sales'].append({'판매채널': row['판매채널'], '판매가': int(row['판매가']), '수량': int(row['수량']), '순이익': int(row['순이익'])})
                date_summary['products'][product_name] = product_summary
            date_summary['products'] = dict(sorted(date_summary['products'].items(), key=lambda x: x[1]['quantity'], reverse=True))
            date_details[date_str] = date_summary
    return render_template('business_dashboard.html', active_page='business_dashboard', total_revenue=total_revenue, gross_profit=gross_profit, total_expenses=total_expenses, net_profit=net_profit, recent_sales_data=recent_sales_data.to_dict('records') if not recent_sales_data.empty else [], available_months=available_months, selected_month=selected_month, start_date=start_date or '', end_date=end_date or '', date_details=date_details)

@app.route('/business/sales')
@login_required
@role_required(menu='business_sales')
def business_sales(membership):
    workspace_id = membership.workspace_id
    products = Product.query.filter_by(workspace_id=workspace_id).all()
    platforms = Platform.query.filter_by(workspace_id=workspace_id).all()

    # --- ⭐️⭐️⭐️ 여기가 핵심 수정 부분입니다 ⭐️⭐️⭐️ ---
    # 1. URL에서 현재 페이지 번호를 가져옵니다. (예: ?page=2) 없으면 1페이지로 시작합니다.
    page = request.args.get('page', 1, type=int)
    
    # 2. 모든 매출을 한 번에 가져오는 대신, 페이지별로 50개씩 끊어서 가져옵니다.
    pagination = Sale.query.filter_by(workspace_id=workspace_id).order_by(Sale.date.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    sales_on_current_page = pagination.items
    # --- ⭐️⭐️⭐️ 수정 끝 ⭐️⭐️⭐️ ---

    if not sales_on_current_page and page == 1:
        return render_template('business_sales.html', active_page='business_sales', products=products, platforms=platforms, sales=[], pagination=None, today=datetime.now().strftime('%Y-%m-%d'))

    return render_template('business_sales.html', 
                           active_page='business_sales', 
                           products=products, 
                           platforms=platforms, 
                           sales=sales_on_current_page, 
                           pagination=pagination,  # ❗️ 페이지네이션 객체를 템플릿으로 전달
                           today=datetime.now().strftime('%Y-%m-%d'))

@app.route('/business/products')
@login_required
@role_required(menu='business_products') # 괄호 안의 'admin'을 삭제
def business_products(membership):
    workspace_id = membership.workspace_id
    products = Product.query.filter_by(workspace_id=workspace_id).all()
    platforms = Platform.query.filter_by(workspace_id=workspace_id).all()
    return render_template('business_products.html', active_page='business_products', products=products, platforms=platforms)

@app.route('/business/products/add', methods=['POST'])
@login_required
@role_required(menu='business_products')
def add_product(membership):
    db.session.add(Product(name=request.form.get('name'), sku=request.form.get('sku', ''), cost_price=int(request.form.get('cost_price', 0)), category=request.form.get('category', ''), workspace_id=membership.workspace_id))
    db.session.commit()
    flash('제품이 추가되었습니다.', 'success')
    return redirect(url_for('business_products'))

@app.route('/business/platforms/add', methods=['POST'])
@login_required
@role_required(menu='business_products')
def add_platform(membership):
    db.session.add(Platform(name=request.form.get('name'), commission_rate=float(request.form.get('commission_rate', 0)), workspace_id=membership.workspace_id))
    db.session.commit()
    flash('판매채널이 추가되었습니다.', 'success')
    return redirect(url_for('business_products'))

@app.route('/business/sales/add', methods=['POST'])
@login_required
@role_required(menu='business_sales')
def add_sale(membership):
    workspace_id = membership.workspace_id
    try:
        product = Product.query.get(int(request.form.get('product_id')))
        platform = Platform.query.get(int(request.form.get('platform_id')))
        if not product or product.workspace_id != workspace_id or not platform or platform.workspace_id != workspace_id:
            flash('잘못된 제품 또는 판매채널입니다.', 'error')
            return redirect(url_for('business_sales'))
        selling_price, quantity = int(request.form.get('selling_price')), int(request.form.get('quantity', 1))
        total_selling_amount = selling_price
        total_cost_amount = product.cost_price * quantity
        commission_amount = int(total_selling_amount * platform.commission_rate / 100)
        net_profit = total_selling_amount - total_cost_amount - commission_amount
        db.session.add(Sale(date=datetime.strptime(request.form.get('date'), '%Y-%m-%d'), product_id=product.id, platform_id=platform.id, selling_price=selling_price, quantity=quantity, total_selling_amount=total_selling_amount, total_cost_amount=total_cost_amount, commission_amount=commission_amount, net_profit=net_profit, workspace_id=workspace_id))
        db.session.commit()
        flash('매출이 등록되었습니다.', 'success')
    except Exception as e: flash(f'오류가 발생했습니다: {str(e)}', 'error')
    return redirect(url_for('business_sales'))


# ❗️❗️❗️ upload_sales 함수를 아래 코드로 통째로 교체해주세요.
@app.route('/business/sales/upload', methods=['POST'])
@login_required
@role_required(menu='business_sales')
def upload_sales(membership):
    workspace_id = membership.workspace_id
    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'message': '파일이 없습니다.'})

    try:
        df = pd.read_excel(file, engine='openpyxl') if file.filename.endswith('.xlsx') else pd.read_csv(file)
        
        products_map = {p.name: p for p in Product.query.filter_by(workspace_id=workspace_id).all()}
        platforms_map = {p.name: p for p in Platform.query.filter_by(workspace_id=workspace_id).all()}
        
        success_count = 0
        fail_count = 0
        error_messages = []
        new_sales_to_add = [] # 임시 저장 리스트

        for index, row in df.iterrows():
            product_name = str(row.get('제품명', '')).strip()
            platform_name = str(row.get('판매채널', '')).strip()
            
            product = products_map.get(product_name)
            platform = platforms_map.get(platform_name)

            if not product:
                fail_count += 1
                error_messages.append(f"{index+2}번째 줄 오류: 제품 '{product_name}'을(를) 찾을 수 없습니다.")
                continue
            if not platform:
                fail_count += 1
                error_messages.append(f"{index+2}번째 줄 오류: 판매채널 '{platform_name}'을(를) 찾을 수 없습니다.")
                continue

            try:
                selling_price = int(row.get('실제판매가', 0))
                quantity = int(row.get('수량', 1))
                date_str = str(row.get('판매일'))
                sale_date = pd.to_datetime(date_str).to_pydatetime()

                total_selling_amount = selling_price
                total_cost_amount = product.cost_price * quantity
                commission_amount = int(total_selling_amount * platform.commission_rate / 100)
                net_profit = total_selling_amount - total_cost_amount - commission_amount

                new_sale = Sale(
                    date=sale_date, product_id=product.id, platform_id=platform.id,
                    selling_price=selling_price, quantity=quantity,
                    total_selling_amount=total_selling_amount, total_cost_amount=total_cost_amount,
                    commission_amount=commission_amount, net_profit=net_profit,
                    workspace_id=workspace_id
                )
                new_sales_to_add.append(new_sale)
                success_count += 1
            except Exception as e:
                fail_count += 1
                error_messages.append(f"{index+2}번째 줄 오류: 날짜나 숫자 형식이 올바르지 않습니다.")

        # 모든 줄을 검사한 후, 오류가 하나도 없을 때만 DB에 최종 저장
        if fail_count > 0:
            db.session.rollback() # 혹시 모르니 롤백
            return jsonify({'success': False, 'message': f"업로드 실패! {fail_count}개의 오류를 먼저 해결해주세요.", 'errors': error_messages})
        else:
            db.session.add_all(new_sales_to_add)
            db.session.commit()
            return jsonify({'success': True, 'message': f'{success_count}개 매출이 성공적으로 추가되었습니다!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'파일 처리 중 예상치 못한 오류 발생: {str(e)}'})


# ❗️❗️❗️ replace_all_sales 함수도 아래의 안전한 코드로 통째로 교체해주세요.
@app.route('/business/sales/replace_all', methods=['POST'])
@login_required
@role_required(menu='business_sales')
def replace_all_sales(membership):
    workspace_id = membership.workspace_id
    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'message': '파일이 없습니다.'})
    
    # 엑셀 파일의 모든 데이터가 유효한지 먼저 끝까지 검사
    try:
        df = pd.read_excel(file, engine='openpyxl') if file.filename.endswith('.xlsx') else pd.read_csv(file)
        products_map = {p.name: p for p in Product.query.filter_by(workspace_id=workspace_id).all()}
        platforms_map = {p.name: p for p in Platform.query.filter_by(workspace_id=workspace_id).all()}
        
        fail_count = 0
        error_messages = []
        
        # 1단계: 유효성 검사만 먼저 수행
        for index, row in df.iterrows():
            product_name = str(row.get('제품명', '')).strip()
            platform_name = str(row.get('판매채널', '')).strip()
            if not products_map.get(product_name) or not platforms_map.get(platform_name):
                fail_count += 1
                error_messages.append(f"{index+2}번째 줄: 제품 또는 판매채널 이름을 찾을 수 없습니다.")
                continue
            try:
                int(row.get('실제판매가', 0)); int(row.get('수량', 1)); pd.to_datetime(str(row.get('판매일')))
            except:
                fail_count += 1
                error_messages.append(f"{index+2}번째 줄: 날짜 또는 숫자 형식을 확인해주세요.")

        # 2단계: 오류가 하나도 없을 때만 삭제 및 추가 진행
        if fail_count > 0:
            return jsonify({'success': False, 'message': f"업로드 실패! {fail_count}개의 오류를 먼저 해결해주세요.", 'errors': error_messages})
        else:
            Sale.query.filter_by(workspace_id=workspace_id).delete()
            for _, row in df.iterrows():
                product = products_map[str(row.get('제품명')).strip()]
                platform = platforms_map[str(row.get('판매채널')).strip()]
                selling_price = int(row.get('실제판매가', 0))
                quantity = int(row.get('수량', 1))
                sale_date = pd.to_datetime(str(row.get('판매일'))).to_pydatetime()
                total_selling_amount = selling_price
                total_cost_amount = product.cost_price * quantity
                commission_amount = int(total_selling_amount * platform.commission_rate / 100)
                net_profit = total_selling_amount - total_cost_amount - commission_amount
                new_sale = Sale(date=sale_date, product_id=product.id, platform_id=platform.id, selling_price=selling_price, quantity=quantity, total_selling_amount=total_selling_amount, total_cost_amount=total_cost_amount, commission_amount=commission_amount, net_profit=net_profit, workspace_id=workspace_id)
                db.session.add(new_sale)
            
            db.session.commit()
            return jsonify({'success': True, 'message': f'데이터를 성공적으로 교체했습니다! ({len(df)}건)'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'파일 처리 중 예상치 못한 오류 발생: {str(e)}'})

@app.route('/business/sales/delete/<sale_id>', methods=['POST'])
@login_required
@role_required(menu='business_sales')
def delete_sale(sale_id, membership):
    sale = Sale.query.get(sale_id)
    if sale and sale.workspace_id == membership.workspace_id:
        db.session.delete(sale)
        db.session.commit()
        return jsonify({'success': True, 'message': '매출이 삭제되었습니다.'})
    return jsonify({'success': False, 'message': '삭제할 매출을 찾을 수 없습니다.'})

@app.route('/business/sales/delete_multiple', methods=['POST'])
@login_required
@role_required(menu='business_sales')
def delete_multiple_sales(membership):
    ids = request.get_json().get('ids', [])
    Sale.query.filter(Sale.id.in_(ids), Sale.workspace_id == membership.workspace_id).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'success': True, 'message': '선택한 매출이 삭제되었습니다.'})

@app.route('/business/products/delete/<int:product_id>', methods=['POST'])
@login_required
@role_required(menu='business_products')
def delete_product(product_id, membership):
    product = Product.query.get(product_id)
    if not product or product.workspace_id != membership.workspace_id:
        return jsonify({'success': False, 'message': '삭제할 제품을 찾을 수 없습니다.'})
    if Sale.query.filter_by(product_id=product_id).count() > 0:
        return jsonify({'success': False, 'message': '이 제품과 연관된 매출 데이터가 있어 삭제할 수 없습니다.'})
    db.session.delete(product)
    db.session.commit()
    return jsonify({'success': True, 'message': f'제품 "{product.name}"이 삭제되었습니다.'})

@app.route('/business/platforms/delete/<int:platform_id>', methods=['POST'])
@login_required
@role_required(menu='business_products')
def delete_platform(platform_id, membership):
    platform = Platform.query.get(platform_id)
    if not platform or platform.workspace_id != membership.workspace_id:
        return jsonify({'success': False, 'message': '삭제할 판매채널을 찾을 수 없습니다.'})
    if Sale.query.filter_by(platform_id=platform_id).count() > 0:
        return jsonify({'success': False, 'message': '이 판매채널과 연관된 매출 데이터가 있어 삭제할 수 없습니다.'})
    db.session.delete(platform)
    db.session.commit()
    return jsonify({'success': True, 'message': f'판매채널 "{platform.name}"이 삭제되었습니다.'})

@app.route('/business/export')
@login_required
def export_business_excel():
    workspace_id = session.get('active_workspace_id')
    if not workspace_id:
        flash('내보낼 데이터가 없습니다.', 'error')
        return redirect(url_for('business_dashboard'))
    # ... (rest is the same)
    sales = Sale.query.filter_by(workspace_id=workspace_id).all()
    if not sales:
        flash('내보낼 매출 내역이 없습니다.', 'info')
        return redirect(url_for('business_dashboard'))
    sales_df = pd.DataFrame([{'날짜': s.date, '제품명': s.product.name, '판매채널': s.platform.name, '판매가': s.selling_price, '수량': s.quantity, '총매출': s.total_selling_amount, '원가': s.total_cost_amount, '수수료': s.commission_amount, '순이익': s.net_profit} for s in sales])
    sales_df['날짜'] = pd.to_datetime(sales_df['날짜'])
    sales_df['월'] = sales_df['날짜'].dt.strftime('%Y-%m')
    selected_month, start_date, end_date = request.args.get('month'), request.args.get('start_date'), request.args.get('end_date')
    df_filtered = sales_df.copy()
    filename = "business_report"
    if start_date and end_date:
        df_filtered = sales_df[(sales_df['날짜'] >= pd.to_datetime(start_date)) & (sales_df['날짜'] <= pd.to_datetime(end_date))]
        filename += f"_{start_date}_to_{end_date}"
    elif selected_month:
        df_filtered = sales_df[sales_df['월'] == selected_month]
        filename += f"_{selected_month}"
    if df_filtered.empty:
        flash('선택된 기간에 내보낼 데이터가 없습니다.', 'info')
        return redirect(url_for('business_dashboard', month=selected_month, start_date=start_date, end_date=end_date))
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        summary_df = pd.DataFrame([{'항목': '총 매출액', '금액': int(df_filtered['총매출'].sum())}, {'항목': '총 순이익', '금액': int(df_filtered['순이익'].sum())}, {'항목': '총 판매수량', '금액': int(df_filtered['수량'].sum())}])
        summary_df.to_excel(writer, sheet_name='요약', index=False)
        product_summary = df_filtered.groupby('제품명').agg({'수량': 'sum', '총매출': 'sum', '순이익': 'sum'}).reset_index().sort_values(by='순이익', ascending=False)
        product_summary.to_excel(writer, sheet_name='제품별 요약', index=False)
        df_filtered['날짜'] = df_filtered['날짜'].dt.strftime('%Y-%m-%d')
        df_filtered[['날짜', '제품명', '판매채널', '판매가', '수량', '총매출', '원가', '수수료', '순이익']].sort_values(by='날짜', ascending=False).to_excel(writer, sheet_name='상세 내역', index=False)
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=f'{filename}.xlsx')


# ============================================

# ============================================
# 🔐 슈퍼 어드민 페이지 (통계 포함 버전)
# ============================================

SUPER_ADMIN_EMAILS = ['ghtes33@gmail.com']

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.email not in SUPER_ADMIN_EMAILS:
            flash('슈퍼 관리자 권한이 필요합니다.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@super_admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_workspaces = Workspace.query.count()
    
    # 전체 통계
    total_expense = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
    total_sales = db.session.query(db.func.sum(Sale.total_selling_amount)).scalar() or 0
    total_sale_profit = db.session.query(db.func.sum(Sale.net_profit)).scalar() or 0
    total_profit = total_sale_profit - total_expense  # 순이익 = 판매이익 - 지출
    
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query = User.query
    if search:
        query = query.filter(
            (User.username.ilike(f'%{search}%')) | 
            (User.email.ilike(f'%{search}%'))
        )
    
    query = query.order_by(User.id.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    users = pagination.items
    
    user_data = []
    for user in users:
        # 유저가 owner인 workspace들 찾기
        owner_workspaces = WorkspaceMember.query.filter_by(user_id=user.id, role='owner').all()
        workspace_ids = [w.workspace_id for w in owner_workspaces]
        
        # 해당 workspace들의 지출/매출/순이익 합계
        user_expense = 0
        user_sales = 0
        user_profit = 0
        
        if workspace_ids:
            user_expense = db.session.query(db.func.sum(Transaction.amount)).filter(Transaction.workspace_id.in_(workspace_ids)).scalar() or 0
            user_sales = db.session.query(db.func.sum(Sale.total_selling_amount)).filter(Sale.workspace_id.in_(workspace_ids)).scalar() or 0
            user_sale_profit = db.session.query(db.func.sum(Sale.net_profit)).filter(Sale.workspace_id.in_(workspace_ids)).scalar() or 0
            user_profit = user_sale_profit - user_expense  # 순이익 = 판매이익 - 지출
        
        user_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'workspace_count': len(owner_workspaces),
            'created_at': user.created_at if hasattr(user, 'created_at') and user.created_at else None,
            'last_login': user.last_login if hasattr(user, 'last_login') and user.last_login else None,
            'expense': user_expense,
            'sales': user_sales,
            'profit': user_profit
        })
    
    return render_template('admin.html',
        total_users=total_users,
        total_workspaces=total_workspaces,
        total_expense=total_expense,
        total_sales=total_sales,
        total_profit=total_profit,
        users=user_data,
        pagination=pagination,
        search=search
    )

@app.route('/admin/user/<int:user_id>')
@login_required
@super_admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    month_filter = request.args.get('month')
    
    memberships = WorkspaceMember.query.filter_by(user_id=user.id).all()
    workspace_ids = [m.workspace_id for m in memberships if m.role == 'owner']
    
    # 가능한 월 목록 가져오기 (Sale 테이블 기준)
    available_months = []
    if workspace_ids:
        sale_dates = db.session.query(Sale.date).filter(Sale.workspace_id.in_(workspace_ids)).all()
        trans_dates = db.session.query(Transaction.date).filter(Transaction.workspace_id.in_(workspace_ids)).all()
        all_dates = [d[0] for d in sale_dates + trans_dates if d[0]]
        available_months = sorted(list(set([d.strftime('%Y-%m') for d in all_dates])), reverse=True)
    
    workspaces = []
    total_expense = 0
    total_sales = 0
    total_profit = 0
    
    for m in memberships:
        workspace = Workspace.query.get(m.workspace_id)
        if workspace:
            # 기본 쿼리
            expense_query = db.session.query(db.func.sum(Transaction.amount)).filter_by(workspace_id=workspace.id)
            sales_query = db.session.query(db.func.sum(Sale.total_selling_amount)).filter_by(workspace_id=workspace.id)
            profit_query = db.session.query(db.func.sum(Sale.net_profit)).filter_by(workspace_id=workspace.id)
            
            # 월 필터 적용
            if month_filter:
                start_date = datetime.strptime(month_filter + '-01', '%Y-%m-%d')
                if start_date.month == 12:
                    end_date = start_date.replace(year=start_date.year + 1, month=1)
                else:
                    end_date = start_date.replace(month=start_date.month + 1)
                
                expense_query = expense_query.filter(Transaction.date >= start_date, Transaction.date < end_date)
                sales_query = sales_query.filter(Sale.date >= start_date, Sale.date < end_date)
                profit_query = profit_query.filter(Sale.date >= start_date, Sale.date < end_date)
            
            ws_expense = expense_query.scalar() or 0
            ws_sales = sales_query.scalar() or 0
            ws_sale_profit = profit_query.scalar() or 0
            ws_profit = ws_sale_profit - ws_expense
            
            if m.role == 'owner':
                total_expense += ws_expense
                total_sales += ws_sales
                total_profit += ws_profit
            
            workspaces.append({
                'id': workspace.id,
                'name': workspace.name,
                'role': m.role,
                'expense': ws_expense,
                'sales': ws_sales,
                'profit': ws_profit
            })
    
    return render_template('admin_user_detail.html',
        user=user,
        workspaces=workspaces,
        total_expense=total_expense,
        total_sales=total_sales,
        total_profit=total_profit,
        available_months=available_months,
        selected_month=month_filter
    )

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash('자기 자신은 삭제할 수 없습니다.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    username = user.username
    
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"'{username}' 회원이 삭제되었습니다.", 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'회원 삭제 중 오류 발생: {str(e)}', 'error')
    
    return redirect(url_for('admin_dashboard'))

# ============================================

with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Database initialization error: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)