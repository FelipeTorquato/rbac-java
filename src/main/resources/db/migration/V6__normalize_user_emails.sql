UPDATE users
SET email = LOWER(BTRIM(email));

ALTER TABLE users
    ADD CONSTRAINT users_email_normalized_check
        CHECK (email = LOWER(BTRIM(email)));