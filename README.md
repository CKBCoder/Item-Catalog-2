# Item Catalog Project

### About
This application provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit, and delete their own items.

### Features
- Proper authentication and authorisation check.
- Full CRUD support using SQLAlchemy and Flask.
- JSON endpoints.
- Implements oAuth using Google Sign-in API.

### Project Structure
```
.
├── client_id.json
├── database_populator.py
├── database_setup.py
├── itemcatalog.db
├── item_catalog.py
├── README.md
├── static
│   └── style.css
└── templates
    ├── delete-item.html
    ├── edit-item.html
    ├── index.html
    ├── items.html
    ├── layout.html
    ├── login.html
    ├── new-item-2.html
    ├── new-item.html
    └── view-item.html
```

### Steps to run this project
1. Run the following command to set up the database:
    ```bash
    python3 database_setup.py
    ```
2. Run the following command to insert dummy values. **If you don't run this, the application will not run.**
    ```bash
    python3 database_populator.py
    ```
3. Run this application:
    ```bash
    python3 item_catalog.py
    ```
4. Open `http://localhost:5000/` in your favourite Web browser, and enjoy.

### Debugging
In case the app doesn't run, make sure to confirm the following points:
- You have run `python3 database_populator.py` before running the application. This is an essential step.
