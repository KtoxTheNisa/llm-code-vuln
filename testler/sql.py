def login(user):
    query = "SELECT * FROM users WHERE name = '" + user + "'"
    return db.execute(query)