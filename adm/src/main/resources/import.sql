INSERT INTO tb_user(username, email, password) VALUES ("admin", "admin@admin.com", "$2a$10$3tMnuVs79BzmyR36qso.f.0veTK.HC4hFAFP4H63wowkuJoWWu7TO");
INSERT INTO tb_user(username, email, password) VALUES ("user", "user@user.com", "$2a$10$3tMnuVs79BzmyR36qso.f.0veTK.HC4hFAFP4H63wowkuJoWWu7TO");

INSERT INTO tb_role(name) VALUES ("admin");
INSERT INTO tb_role(name) VALUES ("user");

INSERT INTO tb_user_role(fk_user_id, fk_role_id) VALUES (1,1);
INSERT INTO tb_user_role(fk_user_id, fk_role_id) VALUES (1,2);

INSERT INTO tb_user_role(fk_user_id, fk_role_id) VALUES (2,2);