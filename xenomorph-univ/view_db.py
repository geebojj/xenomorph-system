import sqlite3
import pandas as pd

conn = sqlite3.connect('xenomorph.db')
df = pd.read_sql_query("SELECT * FROM users", conn)
print(df)
conn.close()