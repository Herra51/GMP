CREATE OR REPLACE PROCEDURE historiser_table(
    table_name VARCHAR(255)
)
BEGIN
    DECLARE trigger_insert VARCHAR(1000);
    DECLARE trigger_update VARCHAR(1000);
    DECLARE trigger_delete VARCHAR(1000);

    -- Génération du trigger pour les INSERT
    SET trigger_insert = CONCAT(
        'CREATE TRIGGER ', table_name, '_after_insert ',
        'AFTER INSERT ON ', table_name, ' ',
        'FOR EACH ROW ',
        'BEGIN ',
        'INSERT INTO base_log (table_name, operation, record_id, record_data, operation_date) ',
        'VALUES (''', table_name, ''', ''INSERT'', NEW.id, ROW_TO_JSON(NEW), NOW()); ',
        'END;'
    );

    -- Génération du trigger pour les UPDATE
    SET trigger_update = CONCAT(
        'CREATE TRIGGER ', table_name, '_after_update ',
        'AFTER UPDATE ON ', table_name, ' ',
        'FOR EACH ROW ',
        'BEGIN ',
        'INSERT INTO base_log (table_name, operation, record_id, record_data, operation_date) ',
        'VALUES (''', table_name, ''', ''UPDATE'', NEW.id, ROW_TO_JSON(NEW), NOW()); ',
        'END;'
    );

    -- Génération du trigger pour les DELETE
    SET trigger_delete = CONCAT(
        'CREATE TRIGGER ', table_name, '_after_delete ',
        'AFTER DELETE ON ', table_name, ' ',
        'FOR EACH ROW ',
        'BEGIN ',
        'INSERT INTO base_log (table_name, operation, record_id, record_data, operation_date) ',
        'VALUES (''', table_name, ''', ''DELETE'', OLD.id, ROW_TO_JSON(OLD), NOW()); ',
        'END;'
    );

    -- Exécution des requêtes pour créer les triggers
    EXECUTE IMMEDIATE trigger_insert;
    EXECUTE IMMEDIATE trigger_update;
    EXECUTE IMMEDIATE trigger_delete;
END;