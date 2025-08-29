import os
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import json
import re
import uuid
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import io
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

# .env 파일에서 환경 변수 로드
load_dotenv()

# --- 기본 앱 설정 ---
app = Flask(__name__)
app.secret_key = 'supersecretkey'

#⭐️⭐️⭐️ 데이터베이스 경로 설정 함수 (수정됨) ⭐️⭐️⭐️
def get_database_url():
    # 환경변수에서 DATABASE_URL을 확인
    database_url = os.getenv('DATABASE_URL')
    if database_url:
        return database_url
    
    # Render 디스크의 실제 마운트 경로 확인 (/var/data/render)
    if os.path.exists('/var/data/render'):
        db_path = '/var/data/render/tracker.db'
        print(f"Using Render persistent disk: {db_path}")
        return f'sqlite:///{db_path}'
    
    # 기타 가능한 Render 경로들
    render_paths = ['/var/data', '/opt/render/project/data', '/data']
    for render_path in render_paths:
        if os.path.exists(render_path):
            db_path = os.path.join(render_path, 'tracker.db')
            print(f"Using render directory: {db_path}")
            return f'sqlite:///{db_path}'
    
    # 로컬 개발 환경용
    instance_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)
    db_path = os.path.join(instance_path, 'tracker.db')
    print(f"Using local instance: {db_path}")
    return f'sqlite:///{db_path}'

# 데이터베이스 URI 설정
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")  # 디버깅용

# .env 파일에서 비밀 키를 읽어오도록 변경
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

# --- 데이터베이스 및 로그인/OAuth 객체 생성 ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- 데이터베이스 모델 ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    profiles = db.relationship('Profile', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transactions = db.relationship('Transaction', backref='profile', lazy=True, cascade="all, delete-orphan")
    rules = db.relationship('Rule', backref='profile', lazy=True, cascade="all, delete-orphan")

class Transaction(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    date = db.Column(db.DateTime, nullable=False)
    merchant = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(100), nullable=False, default='미분류')
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    keyword = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    profile_id = db.Column(db.Integer, db.ForeignKey('profile.id'), nullable=False)


# --- 로그인 관련 함수 ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
            user = User(
                email=user_info['email'],
                username=user_info.get('name', user_info['email'])
            )
            db.session.add(user)
            db.session.commit()
            
            default_profile = Profile(name="기본 프로필", user_id=user.id)
            db.session.add(default_profile)
            db.session.commit()

        login_user(user)
        
        first_profile = Profile.query.filter_by(user_id=user.id).first()
        if first_profile:
            session['active_profile_id'] = first_profile.id
            
        return redirect(url_for('index'))
    
    flash('Google 로그인에 실패했습니다. 다시 시도해주세요.', 'error')
    return redirect(url_for('login'))


# --- 데이터 처리 헬퍼 함수 ---
def clean_merchant_name(name):
    name_lower = str(name).lower()
    if 'facebk' in name_lower or 'facebook' in name_lower: return 'FACEBOOK'
    if 'google' in name_lower or '구글' in name_lower: return 'Google'
    return name

def apply_category(df, profile_id):
    rules = Rule.query.filter_by(profile_id=profile_id).all()
    df_copy = df.copy()
    column_mapping = {
        '거래일시': '날짜', '거래일자': '날짜', '사용일': '날짜',
        '거래처': '거래처명', '거래내용': '거래처명', '내용': '거래처명', '가맹점명': '거래처명',
        '출금액': '금액', '사용금액': '금액', '거래금액': '금액',
    }
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
            if rule.keyword.lower().strip() in desc_processed:
                return rule.category
        return '미분류'
    df_copy['카테고리'] = df_copy['거래처명'].apply(find_category)
    return df_copy


# --- 템플릿 공용 데이터 ---
@app.context_processor
def inject_profiles():
    if current_user.is_authenticated:
        profiles = Profile.query.filter_by(user_id=current_user.id).all()
        active_profile_id = session.get('active_profile_id')
        active_profile = Profile.query.get(active_profile_id) if active_profile_id else None
        return dict(profiles=profiles, active_profile=active_profile)
    return dict(profiles=[], active_profile=None)


# --- 라우트 (페이지) 정의 ---
@app.route('/profiles')
@login_required
def manage_profiles():
    return render_template('profiles.html', active_page='profiles')

@app.route('/profiles/add', methods=['POST'])
@login_required
def add_profile():
    profile_name = request.form.get('profile_name')
    if profile_name:
        new_profile = Profile(name=profile_name, user_id=current_user.id)
        db.session.add(new_profile)
        db.session.commit()
        flash(f"'{profile_name}' 프로필이 생성되었습니다.", 'success')
        session['active_profile_id'] = new_profile.id
    else:
        flash('프로필 이름을 입력해주세요.', 'error')
    return redirect(url_for('manage_profiles'))

@app.route('/profiles/select/<int:profile_id>')
@login_required
def select_profile(profile_id):
    profile = Profile.query.get(profile_id)
    if profile and profile.user_id == current_user.id:
        session['active_profile_id'] = profile_id
    else:
        flash('유효하지 않은 프로필입니다.', 'error')
    return redirect(request.referrer or url_for('index'))

@app.route('/profiles/delete/<int:profile_id>', methods=['POST'])
@login_required
def delete_profile(profile_id):
    profile = Profile.query.get(profile_id)
    if profile and profile.user_id == current_user.id:
        db.session.delete(profile)
        db.session.commit()
        flash(f"'{profile.name}' 프로필과 모든 데이터가 삭제되었습니다.", 'success')
        if session.get('active_profile_id') == profile_id:
            session.pop('active_profile_id', None)
    else:
        flash('삭제할 프로필을 찾을 수 없거나 권한이 없습니다.', 'error')
    return redirect(url_for('manage_profiles'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('이미 존재하는 사용자 이름입니다.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.', 'error')
            return redirect(url_for('register'))
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('회원가입이 완료되었습니다! 로그인해주세요.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('사용자 이름 또는 비밀번호가 올바르지 않습니다.', 'error')
            return redirect(url_for('login'))
        login_user(user)
        first_profile = Profile.query.filter_by(user_id=user.id).first()
        if first_profile:
            session['active_profile_id'] = first_profile.id
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    session.pop('active_profile_id', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash('데이터를 보려면 먼저 프로필을 선택하거나 생성해주세요.', 'info')
        return redirect(url_for('manage_profiles'))
    
    transactions = Transaction.query.filter_by(profile_id=profile_id).all()
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
            for t in trans:
                t['금액'] = int(t['금액'])
            merchant_details[merchant] = {'total': total, 'transactions': trans}
        category_details[category] = dict(sorted(merchant_details.items(), key=lambda item: item[1]['total'], reverse=True))

    return render_template('index.html', active_page='dashboard', category_totals=category_totals, total_expense=total_expense, available_months=available_months, selected_month=selected_month, start_date=request.args.get('start_date', ''), end_date=request.args.get('end_date', ''), category_details=category_details)

@app.route('/classify', methods=['GET', 'POST'])
@login_required
def show_results():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash('데이터를 업로드하려면 먼저 프로필을 선택하거나 생성해주세요.', 'info')
        return redirect(url_for('manage_profiles'))

    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('파일이 선택되지 않았습니다.', 'error')
            return redirect(url_for('show_results'))
        try:
            if file.filename.endswith('.csv'):
                df_new = pd.read_csv(file)
            else:
                df_new = pd.read_excel(file, engine='openpyxl')
                
            classified_df = apply_category(df_new, profile_id)
            if classified_df is None:
                return redirect(url_for('show_results'))

            action = request.form.get('action', 'append')
            if action == 'upload':
                Transaction.query.filter_by(profile_id=profile_id).delete()
                flash('기존 모든 데이터가 삭제되었습니다.', 'info')
            for _, row in classified_df.iterrows():
                transaction = Transaction(
                    date=row['날짜'],
                    merchant=row['거래처명'],
                    amount=row['금액'],
                    category=row['카테고리'],
                    profile_id=profile_id
                )
                db.session.add(transaction)
            db.session.commit()
            flash('데이터가 성공적으로 처리되었습니다!', 'success')
        except Exception as e:
            flash(f'파일 처리 중 오류 발생: {str(e)}', 'error')
        return redirect(url_for('show_results'))

    base_query = Transaction.query.filter_by(profile_id=profile_id)
    all_transactions = base_query.all()
    if not all_transactions:
        return render_template('classify.html', active_page='classify', records=[], unique_categories=[], available_months=[])
    all_dates = [t.date for t in all_transactions]
    all_categories = {t.category for t in all_transactions}
    available_months = sorted({d.strftime('%Y-%m') for d in all_dates}, reverse=True)
    unique_categories = sorted(list(all_categories))
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

@app.route('/delete_item/<item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    month_filter = request.form.get('month_filter')
    category_filter = request.form.get('category_filter')
    item_to_delete = Transaction.query.get(item_id)
    if item_to_delete and item_to_delete.profile.user_id == current_user.id:
        db.session.delete(item_to_delete)
        db.session.commit()
        flash('항목이 삭제되었습니다.', 'success')
    else:
        flash('삭제할 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
    redirect_args = {}
    if month_filter:
        redirect_args['month_filter'] = month_filter
    if category_filter:
        redirect_args['category_filter'] = category_filter
    return redirect(url_for('show_results', **redirect_args))

@app.route('/rules', methods=['GET', 'POST'])
@login_required
def manage_rules():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash('규칙을 관리하려면 먼저 프로필을 선택하거나 생성해주세요.', 'info')
        return redirect(url_for('manage_profiles'))
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        category = request.form.get('category')
        if keyword and category:
            new_rule = Rule(keyword=keyword, category=category, profile_id=profile_id)
            db.session.add(new_rule)
            db.session.commit()
            flash('새 규칙이 추가되었습니다.', 'success')
        else:
            flash('키워드와 카테고리를 모두 입력해주세요.', 'error')
        return redirect(url_for('manage_rules'))
    rules = Rule.query.filter_by(profile_id=profile_id).all()
    return render_template('rules.html', active_page='rules', rules=rules)

@app.route('/delete_rule/<int:rule_id>', methods=['POST'])
@login_required
def delete_rule(rule_id):
    rule_to_delete = Rule.query.get(rule_id)
    if rule_to_delete and rule_to_delete.profile.user_id == current_user.id:
        db.session.delete(rule_to_delete)
        db.session.commit()
        flash('규칙이 삭제되었습니다.', 'success')
    else:
        flash('삭제할 규칙을 찾을 수 없거나 권한이 없습니다.', 'error')
    return redirect(url_for('manage_rules'))

@app.route('/reclassify_all', methods=['POST'])
@login_required
def reclassify_all_data():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash('재분류하려면 먼저 프로필을 선택해주세요.', 'info')
        return redirect(url_for('manage_rules'))
    transactions = Transaction.query.filter_by(profile_id=profile_id).all()
    if not transactions:
        flash('재분류할 데이터가 없습니다.', 'info')
        return redirect(url_for('manage_rules'))
    trans_data = [{'날짜': t.date, '거래처명': t.merchant, '금액': t.amount, 'id': t.id} for t in transactions]
    df = pd.DataFrame(trans_data)
    reclassified_df = apply_category(df, profile_id)
    if reclassified_df is not None:
        for _, row in reclassified_df.iterrows():
            trans_to_update = Transaction.query.get(row['id'])
            if trans_to_update:
                trans_to_update.category = row['카테고리']
        db.session.commit()
        flash('모든 데이터가 현재 규칙으로 다시 분류되었습니다!', 'success')
    else:
        flash('데이터 재분류 중 오류가 발생했습니다.', 'error')
    return redirect(url_for('manage_rules'))

@app.route('/edit_transaction/<item_id>', methods=['POST'])
@login_required
def edit_transaction(item_id):
    item_to_edit = Transaction.query.get(item_id)
    if item_to_edit and item_to_edit.profile.user_id == current_user.id:
        try:
            new_date_str = request.form.get('date')
            new_merchant = request.form.get('merchant')
            new_amount = request.form.get('amount')
            new_category = request.form.get('category')
            item_to_edit.date = datetime.strptime(new_date_str, '%Y-%m-%d')
            item_to_edit.merchant = new_merchant
            item_to_edit.amount = int(new_amount)
            item_to_edit.category = new_category
            db.session.commit()
            flash('거래내역이 성공적으로 수정되었습니다.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'수정 중 오류가 발생했습니다: {e}', 'error')
    else:
        flash('수정할 항목을 찾을 수 없거나 권한이 없습니다.', 'error')
    redirect_args = {k: v for k, v in request.form.items() if k in ['month_filter', 'category_filter']}
    return redirect(url_for('show_results', **redirect_args))

@app.route('/export')
@login_required
def export_excel():
    profile_id = session.get('active_profile_id')
    if not profile_id:
        flash('내보낼 데이터가 없습니다. 먼저 프로필을 선택해주세요.', 'error')
        return redirect(url_for('index'))

    transactions = Transaction.query.filter_by(profile_id=profile_id).all()
    if not transactions:
        flash('내보낼 거래 내역이 없습니다.', 'info')
        return redirect(url_for('index'))

    trans_data = [{'날짜': t.date, '거래처명': t.merchant, '금액': t.amount, '카테고리': t.category} for t in transactions]
    df = pd.DataFrame(trans_data)
    df['날짜'] = pd.to_datetime(df['날짜'], errors='coerce')
    df.dropna(subset=['날짜'], inplace=True)
    df['월'] = df['날짜'].dt.strftime('%Y-%m')
    
    selected_month = request.args.get('month')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    df_filtered = df.copy()
    filename = "expense_report"

    if start_date and end_date:
        start_date_dt = pd.to_datetime(start_date)
        end_date_dt = pd.to_datetime(end_date)
        df_filtered = df[(df['날짜'] >= start_date_dt) & (df['날짜'] <= end_date_dt)]
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
        # 1. 전체 요약 시트 생성
        category_totals = df_classified.groupby('카테고리')['금액'].sum().reset_index()
        total_expense = df_classified['금액'].sum()
        
        total_row = pd.DataFrame([{'카테고리': '총 지출', '금액': total_expense}])
        summary_df = pd.concat([category_totals, total_row], ignore_index=True)
        
        summary_df.to_excel(writer, sheet_name='요약', index=False)

        # 2. 카테고리별 상세 내역 시트 생성
        df_classified['날짜'] = df_classified['날짜'].dt.strftime('%Y-%m-%d')
        for category, group_df in df_classified.groupby('카테고리'):
            merchant_summary = group_df.groupby('거래처명')['금액'].sum().reset_index().sort_values(by='금액', ascending=False)
            merchant_summary.to_excel(writer, sheet_name=f'{category} 요약', index=False)
            
            group_df[['날짜', '거래처명', '금액']].sort_values(by='날짜', ascending=False).to_excel(writer, sheet_name=f'{category} 상세', index=False)

    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{filename}.xlsx'
    )

# ⭐️⭐️⭐️ 앱 시작 전에 데이터베이스 초기화 (수정됨) ⭐️⭐️⭐️
with app.app_context():
    try:
        # 데이터베이스 테이블 생성
        db.create_all()
        print("데이터베이스 테이블이 생성되었습니다.")
        
        # 테스트 사용자가 없으면 생성
        if not User.query.filter_by(username='testuser').first():
            test_user = User(
                username='testuser',
                email='test@example.com',
                password_hash=generate_password_hash('password')
            )
            db.session.add(test_user)
            db.session.commit()

            # 기본 프로필 생성
            default_profile = Profile(name="기본 프로필", user_id=test_user.id)
            db.session.add(default_profile)
            db.session.commit()
            print("기본 사용자와 프로필이 생성되었습니다.")
    except Exception as e:
        print(f"데이터베이스 초기화 오류: {e}")

if __name__ == '__main__':
    # 로컬 개발용
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)