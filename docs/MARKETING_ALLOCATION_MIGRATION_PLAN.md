# 광고비 귀속 additive migration 운영 계획

이 문서는 코드/fixture 검증 이후 실제 SBROCOR Finance production DB에 schema version 2를 적용하기 전 승인용 계획이다. 이 PR은 production DB, MoneyLog `tracker.db`, COPY manifest를 실행하거나 변경하지 않는다.

## 변경되는 schema

- 신규 `brand` 테이블
- 기존 `product`에 nullable `brand_id` 컬럼과 인덱스 추가
- 신규 `marketing_allocation` 테이블과 조회 인덱스 추가
- `schema_version`에 version 2 기록

변경하지 않는 항목:

- `finance_transaction` row와 `category`
- `sale` row와 모든 저장 금액
- `ad_spend` row
- 기존 Product의 브랜드 값: migration 직후 모두 `NULL`
- MoneyLog `tracker.db`

## 적용 전 backup

1. 배포 시점의 `SBROCOR_FINANCE_DB_PATH`가 `tracker.db`가 아님을 재확인한다.
2. Finance 쓰기를 짧게 중단한다.
3. `scripts/backup_sqlite.py`의 online backup으로 별도 파일을 만든다.
4. `scripts/verify_sqlite_backup.py`로 `PRAGMA integrity_check`, 테이블/건수/hash를 확인한다.
5. 원본과 backup의 다음 값을 기록한다.
   - `finance_transaction`: count, `SUM(amount)`, category별 count/sum
   - `sale`: count와 네 개 금액 컬럼 합계
   - `ad_spend`: count, `SUM(spend)`
   - `product`: count
6. backup 파일의 SHA-256과 보관 위치를 승인 기록에 남긴다.

## 적용

1. 승인된 SBROCOR Finance DB 복사본에서 먼저 `initialize_database()`를 실행한다.
2. schema와 aggregate가 일치하는지 확인한다.
3. 실제 Finance DB에 동일 명령을 1회 실행한다.
4. `brand`, `marketing_allocation`, `product.brand_id` 존재를 확인한다.
5. 기존 Product의 `brand_id IS NOT NULL` 건수가 0인지 확인한다.
6. 기존 광고비 중 allocation이 자동 생성되지 않았는지 확인한다.
7. 위 backup aggregate와 적용 후 aggregate를 다시 비교한다.

## rollback

additive 컬럼/테이블을 production에서 즉시 DROP하지 않는다. 문제가 생기면:

1. Finance 쓰기 중단
2. 새 UI/API route 비활성화 또는 이전 application revision으로 rollback
3. version 2 테이블은 미사용 상태로 보존
4. schema 자체가 DB 동작을 방해하는 경우에만 승인 후 backup 파일을 새 경로로 복원
5. 복원 DB의 integrity/count/합계를 검증한 뒤 `SBROCOR_FINANCE_DB_PATH`를 복원본으로 전환

원본 backup을 덮어쓰거나 삭제하지 않는다. `tracker.db`에는 어떤 rollback 명령도 실행하지 않는다.

## 승인 게이트

다음이 모두 확인되기 전 production migration을 실행하지 않는다.

- fixture 전체 테스트 PASS
- SBROCOR lint/TypeScript/build PASS
- backup/restore rehearsal PASS
- 대상 DB 절대경로 확인
- production write window 승인
- 적용 전후 aggregate 비교 쿼리 승인

