import cmd
import sqlite3
import schedule
import time
from getpass import getpass
import bcrypt

class SmartHomeCLI(cmd.Cmd):
    intro = "Welcome to the Smart Home Automation System. Type help or ? to list commands.\n"
    prompt = '(smart-home) '
    
    def __init__(self):
        super().__init__()
        self.db = sqlite3.connect('smarthome.db')
        self.create_tables()
        self.current_user = None

    def create_tables(self):
        with self.db:
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    type TEXT,
                    status TEXT,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    action TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                )
            """)
    
    def do_register(self, arg):
        'Register a new user: register username'
        username = arg
        password = getpass("Password: ")
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            with self.db:
                self.db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            print("User registered successfully.")
        except sqlite3.IntegrityError:
            print("Username already exists.")
    
    def do_login(self, arg):
        'Login as an existing user: login username'
        username = arg
        password = getpass("Password: ")
        user = self.db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            self.current_user = user
            print("Logged in successfully.")
        else:
            print("Invalid username or password.")
    
    def do_add_device(self, arg):
        'Add a new device: add_device "Device Name" type'
        if self.current_user:
            name, dev_type = arg.split()
            with self.db:
                self.db.execute("INSERT INTO devices (name, type, status, user_id) VALUES (?, ?, ?, ?)",
                                (name, dev_type, 'off', self.current_user[0]))
            print(f"Device {name} added successfully.")
        else:
            print("You need to log in first.")
    
    def do_list_devices(self, arg):
        'List all devices'
        if self.current_user:
            devices = self.db.execute("SELECT id, name, type, status FROM devices WHERE user_id = ?", (self.current_user[0],)).fetchall()
            for device in devices:
                print(f"ID: {device[0]}, Name: {device[1]}, Type: {device[2]}, Status: {device[3]}")
        else:
            print("You need to log in first.")
    
    def do_control_device(self, arg):
        'Control a device: control_device device_id action'
        if self.current_user:
            device_id, action = arg.split()
            with self.db:
                self.db.execute("UPDATE devices SET status = ? WHERE id = ? AND user_id = ?",
                                (action, device_id, self.current_user[0]))
                self.db.execute("INSERT INTO logs (device_id, action) VALUES (?, ?)", (device_id, action))
            print(f"Device {device_id} turned {action}.")
        else:
            print("You need to log in first.")
    
    def do_view_logs(self, arg):
        'View logs for a device: view_logs device_id'
        if self.current_user:
            device_id = arg
            logs = self.db.execute("SELECT action, timestamp FROM logs WHERE device_id = ?", (device_id,)).fetchall()
            for log in logs:
                print(f"Action: {log[0]}, Timestamp: {log[1]}")
        else:
            print("You need to log in first.")
    
    def do_dashboard(self, arg):
        'View the dashboard'
        if self.current_user:
            devices = self.db.execute("SELECT name, status FROM devices WHERE user_id = ?", (self.current_user[0],)).fetchall()
            print("Current device statuses:")
            for device in devices:
                print(f"{device[0]}: {device[1]}")
        else:
            print("You need to log in first.")
    
    def do_exit(self, arg):
        'Exit the Smart Home CLI'
        print("Goodbye!")
        return True

if __name__ == '__main__':
    SmartHomeCLI().cmdloop()
