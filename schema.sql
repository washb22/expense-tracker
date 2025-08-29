DROP TABLE IF EXISTS rules;

CREATE TABLE rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  keyword TEXT NOT NULL,
  category TEXT NOT NULL
);

INSERT INTO rules (keyword, category) VALUES
('스타벅스', '식비'),
('배달의민족', '식비'),
('카카오택시', '교통비'),
('네이버', '광고비'),
('구글', '광고비');