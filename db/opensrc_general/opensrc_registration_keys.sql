create table opensrc_general.opensrc_registration_keys
(
    id            int auto_increment
        primary key,
    `key`         text                                   not null,
    status        tinyint(1) default 1                   not null,
    creation_date timestamp  default current_timestamp() not null
);


