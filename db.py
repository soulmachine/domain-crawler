"""Database abstraction layer supporting MongoDB and SQLite."""
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from datetime import datetime

# DOMAIN_DB_URI = os.environ.get('DOMAIN_DB_URI', 'mongodb://localhost:27017')
DOMAIN_DB_URI = os.environ.get('DOMAIN_DB_URI', 'file:domains.sqlite')


def get_db():
    if DOMAIN_DB_URI.startswith('mongodb://'):
        return MongoDBBackend(DOMAIN_DB_URI)
    else:
        return SQLiteBackend(DOMAIN_DB_URI)


class DBBackend(ABC):
    @abstractmethod
    def get_record(self, target, domain):
        pass

    @abstractmethod
    def insert(self, target, domain, registered, raw_info=None):
        pass

    @abstractmethod
    def update(self, target, domain, registered, raw_info=None):
        pass


class MongoDBBackend(DBBackend):
    def __init__(self, uri):
        import pymongo
        self.client = pymongo.MongoClient(uri)
        self.db = self.client.domain

    def get_record(self, target, domain):
        return self.db[target].find_one({'_id': domain}, {'_id': 1, 'updatedAt': 1})

    def insert(self, target, domain, registered, raw_info=None):
        info = {
            '_id': domain,
            'registered': registered,
            'createdAt': datetime.now(),
            'updatedAt': datetime.now(),
        }
        if raw_info is not None:
            info['rawInfo'] = raw_info
        self.db[target].insert_one(info)

    def update(self, target, domain, registered, raw_info=None):
        update_fields = {'registered': registered, 'updatedAt': datetime.now()}
        if raw_info is not None:
            update_fields['rawInfo'] = raw_info
        self.db[target].update_one({'_id': domain}, {'$set': update_fields})


class SQLiteBackend(DBBackend):
    def __init__(self, db_path):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, uri=True)

    def _ensure_db(self):
        """Create the database file if it doesn't exist."""
        conn = self._get_conn()
        conn.close()

    def _ensure_table(self, conn, target):
        conn.execute(
            f'CREATE TABLE IF NOT EXISTS [{target}] ('
            f'  domain TEXT PRIMARY KEY,'
            f'  registered INTEGER NOT NULL,'
            f'  raw_info TEXT,'
            f'  created_at TEXT NOT NULL,'
            f'  updated_at TEXT NOT NULL'
            f')'
        )

    def get_record(self, target, domain):
        with self._lock:
            conn = self._get_conn()
            try:
                self._ensure_table(conn, target)
                row = conn.execute(
                    f'SELECT domain, updated_at FROM [{target}] WHERE domain = ?',
                    (domain,),
                ).fetchone()
                if row is None:
                    return None
                return {'_id': row[0], 'updatedAt': datetime.fromisoformat(row[1])}
            finally:
                conn.close()

    def insert(self, target, domain, registered, raw_info=None):
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                self._ensure_table(conn, target)
                conn.execute(
                    f'INSERT INTO [{target}] (domain, registered, raw_info, created_at, updated_at)'
                    f' VALUES (?, ?, ?, ?, ?)',
                    (domain, int(registered), raw_info, now, now),
                )
                conn.commit()
            finally:
                conn.close()

    def update(self, target, domain, registered, raw_info=None):
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                self._ensure_table(conn, target)
                if raw_info is not None:
                    conn.execute(
                        f'UPDATE [{target}] SET registered = ?, raw_info = ?, updated_at = ?'
                        f' WHERE domain = ?',
                        (int(registered), raw_info, now, domain),
                    )
                else:
                    conn.execute(
                        f'UPDATE [{target}] SET registered = ?, updated_at = ?'
                        f' WHERE domain = ?',
                        (int(registered), now, domain),
                    )
                conn.commit()
            finally:
                conn.close()
