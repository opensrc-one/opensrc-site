create table opensrc_general.opensrc_users
(
    uid         int auto_increment
        primary key,
    username    text                                         not null,
    password    longtext collate utf8mb4_bin                 not null
        check (json_valid(`password`)),
    user_groups longtext collate utf8mb4_bin default '["0"]' not null
        check (json_valid(`user_groups`)),
    mnemonic    longtext collate utf8mb4_bin                 not null
        check (json_valid(`mnemonic`)),
    totp        longtext collate utf8mb4_bin                 null
        check (json_valid(`totp`)),
    login_key   longtext collate utf8mb4_bin                 null
        check (json_valid(`login_key`)),
    data_key    longtext collate utf8mb4_bin                 not null
        check (json_valid(`data_key`))
);


