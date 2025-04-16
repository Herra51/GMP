import pymysql
from flask import session

def get_categories():
    from main import get_db_connection
    conn = get_db_connection()
    cursor = conn.cursor()
    user_id = session['user_id']
    
    try:
        cursor.execute("SELECT * FROM password_category where user_id = %s", (user_id,))
        categories = cursor.fetchall() or []
        print("categories", categories)
        return categories
    except pymysql.Error as e:
        print(f"An error occurred Mysql: {e}")
        return []
    except Exception as e:
        print(e)
        return []
    finally:
        conn.close()
        
