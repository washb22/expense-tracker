import json
from app import app, db, Rule, User

# 마이그레이션할 사용자 ID (현재는 테스트 사용자인 1)
USER_ID = 1
JSON_FILE = 'db.json'

def migrate():
    """
    db.json 파일의 규칙을 SQLite 데이터베이스로 옮깁니다.
    """
    with app.app_context():
        # 1. JSON 파일에서 기존 규칙 로드
        try:
            with open(JSON_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                rules_from_json = data.get('rules', [])
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"'{JSON_FILE}'을 찾을 수 없거나 읽을 수 없습니다.")
            return

        # 2. DB에 사용자가 존재하는지 확인
        user = User.query.get(USER_ID)
        if not user:
            print(f"ID가 {USER_ID}인 사용자를 찾을 수 없습니다. db_init.py를 먼저 실행하세요.")
            return

        # 3. DB에 이미 규칙이 있는지 확인하고, 없으면 추가
        existing_keywords = {rule.keyword for rule in Rule.query.filter_by(user_id=USER_ID).all()}
        
        new_rules_added = 0
        for rule_data in rules_from_json:
            if rule_data['keyword'] not in existing_keywords:
                new_rule = Rule(
                    keyword=rule_data['keyword'],
                    category=rule_data['category'],
                    user_id=USER_ID
                )
                db.session.add(new_rule)
                existing_keywords.add(rule_data['keyword'])
                new_rules_added += 1
        
        if new_rules_added > 0:
            db.session.commit()
            print(f"{new_rules_added}개의 새 규칙을 데이터베이스로 옮겼습니다.")
        else:
            print("데이터베이스에 이미 모든 규칙이 존재합니다. 추가할 새 규칙이 없습니다.")

if __name__ == '__main__':
    migrate()
