CREATE TABLE user (
    id_user INT auto_increment,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id_user)
);

CREATE TABLE password (
    id_password INT auto_increment,
    user_id INT NOT NULL,
    category_id INT NOT NULL DEFAULT 0,
    platform_name VARCHAR(50) NOT NULL,
    login VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user (id_user),
    PRIMARY KEY (id_password)
);

CREATE TABLE password_category (
    id_password_category INT auto_increment,
    user_id INT NOT NULL,
    category_name VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user (id_user),
    PRIMARY KEY (id_password_category)
);

CREATE TABLE secret_message (
    id_secret_message INT auto_increment,
    user_id INT NOT NULL,
    message TEXT NOT NULL,
    is_viewed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user (id_user),
    PRIMARY KEY (id_secret_message)
);

CREATE TABLE histo_password_modification (
    id_histo_password_modification INT auto_increment,
    table_name VARCHAR(50) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    record_id INT NOT NULL,
    record_data JSON NOT NULL,
    operation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (
        id_histo_password_modification
    )
);

CREATE TABLE shared_password (
    id_shared_password INT auto_increment,
    password_id INT NOT NULL,
    share_token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id_shared_password),
    FOREIGN KEY (password_id) REFERENCES password (id_password) ON DELETE CASCADE
);