from app import app, db, User, Profile
from werkzeug.security import generate_password_hash

with app.app_context():
    print("데이터베이스 테이블을 생성합니다...")
    db.create_all()
    
    if not User.query.filter_by(username='testuser').first():
        print("테스트 사용자와 기본 프로필을 생성합니다...")
        test_user = User(
            username='testuser',
            email='test@example.com',
            password_hash=generate_password_hash('password')
        )
        db.session.add(test_user)
        # 사용자를 먼저 커밋하여 ID를 부여받습니다.
        db.session.commit()

        # 해당 사용자의 기본 프로필을 생성합니다.
        default_profile = Profile(name="기본 프로필", user_id=test_user.id)
        db.session.add(default_profile)
        db.session.commit()
        print("테스트 사용자 및 프로필 생성 완료.")

    print("데이터베이스 초기화 완료.")
