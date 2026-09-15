INSERT INTO roles (id, name)
VALUES ('d25642d9-1662-4db1-9685-649033333331', 'ROLE_ADMIN'),
       ('d25642d9-1662-4db1-9685-649033333332', 'ROLE_MANAGER'),
       ('d25642d9-1662-4db1-9685-649033333333', 'ROLE_USER');

INSERT INTO users (id, name, email, password_hash, enabled)
VALUES ('a34653e0-1662-4db1-9685-649033333331', 'Admin', 'admin@app.com',
        '$2a$12$8mTFtSeQTIZXxfhmZmrY/OFYYKNtf4reeIojUGhsWnIBStYM.Q4XG', true),
       ('a34653e0-1662-4db1-9685-649033333332', 'Manager', 'manager@app.com',
        '$2a$12$8mTFtSeQTIZXxfhmZmrY/OFYYKNtf4reeIojUGhsWnIBStYM.Q4XG', true),
       ('a34653e0-1662-4db1-9685-649033333333', 'User', 'user@app.com',
        '$2a$12$8mTFtSeQTIZXxfhmZmrY/OFYYKNtf4reeIojUGhsWnIBStYM.Q4XG', true);

INSERT INTO user_roles (user_id, role_id)
VALUES ('a34653e0-1662-4db1-9685-649033333331', 'd25642d9-1662-4db1-9685-649033333331'),
       ('a34653e0-1662-4db1-9685-649033333332', 'd25642d9-1662-4db1-9685-649033333332'),
       ('a34653e0-1662-4db1-9685-649033333333', 'd25642d9-1662-4db1-9685-649033333333');