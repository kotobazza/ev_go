CREATE TABLE IF NOT EXISTS encrypted_votes (
    voting_id INT NOT NULL,
    label TEXT NOT NULL,
    encrypted_vote TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);


CREATE TABLE IF NOT EXISTS merklie_roots(
    id SERIAL PRIMARY KEY,
    voting_id INT NOT NULL,
    root_value TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL
);


CREATE TABLE IF NOT EXISTS public_encrypted_votes(
    voting_id INT NOT NULL,
    label TEXT NOT NULL,
    encrypted_vote TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);