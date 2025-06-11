-- format : delimiter //
delimiter /
/

CREATE OR REPLACE PROCEDURE historiser_table()
BEGIN
    -- Supprimer les triggers s'ils existent déjà
    DROP TRIGGER IF EXISTS password_after_insert;
    DROP TRIGGER IF EXISTS password_after_update;
    DROP TRIGGER IF EXISTS password_after_delete;
    
    DECLARE trigger_insert VARCHAR(2000);
    DECLARE trigger_update VARCHAR(2000);
    DECLARE trigger_delete VARCHAR(2000);

    SET trigger_insert = '
        CREATE TRIGGER password_after_insert
        AFTER INSERT ON password
        FOR EACH ROW
        BEGIN
            INSERT INTO histo_password_modification (table_name, operation, record_id, record_data, operation_date)
        VALUES (''password'', ''INSERT'', NEW.id_password,
            JSON_OBJECT(
                ''id_password'', NEW.id_password,
                ''user_id'', NEW.user_id,
                ''category_id'', NEW.category_id,
                ''platform_name'', NEW.platform_name,
                ''login'', NEW.login,
                ''password'', NEW.password,
                ''url'', NEW.url
            ),
            NOW());
        END;';

    SET trigger_update = '
        CREATE TRIGGER password_after_update
        AFTER UPDATE ON password
        FOR EACH ROW
        BEGIN
            INSERT INTO histo_password_modification (table_name, operation, record_id, record_data, operation_date)
            VALUES (''password'', ''UPDATE'', NEW.id_password,
                JSON_OBJECT(
                    ''id_password'', NEW.id_password,
                    ''user_id'', NEW.user_id,
                    ''category_id'', NEW.category_id,
                    ''platform_name'', NEW.platform_name,
                    ''login'', NEW.login,
                    ''password'', NEW.password,
                    ''url'', NEW.url
                ),
                NOW());
        END;';

    SET trigger_delete = '
        CREATE TRIGGER password_after_delete
        AFTER DELETE ON password
        FOR EACH ROW
        BEGIN
            INSERT INTO histo_password_modification (table_name, operation, record_id, record_data, operation_date)
            VALUES (''password'', ''DELETE'', OLD.id_password,
                JSON_OBJECT(
                    ''id_password'', OLD.id_password,
                    ''user_id'', OLD.user_id,
                    ''category_id'', OLD.category_id,
                    ''platform_name'', OLD.platform_name,
                    ''login'', OLD.login,
                    ''password'', OLD.password,
                    ''url'', OLD.url
                ),
                NOW());
        END;';

    EXECUTE IMMEDIATE trigger_insert;
    EXECUTE IMMEDIATE trigger_update;
    EXECUTE IMMEDIATE trigger_delete;

/*
format :

END //
delimiter ;
*/
END
/
/

delimiter;

CALL historiser_table ();