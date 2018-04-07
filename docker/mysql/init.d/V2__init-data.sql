INSERT INTO users (id, username, password, nickname, email, enabled)
VALUES (1, 'user', '{noop}password', 'User', 'user@example.com', TRUE);

INSERT INTO authorities (id, user_id, authority)
VALUES (1, 1, 'ROLE_ADMIN');
