import json
import os
from datetime import datetime
from typing import Dict, List, Tuple
import mysql.connector

class UserAnalytics: 
    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.analytics_file = "user_analytics.json"
        self.initialize_analytics_table()

    def initialize_analytics_table(self):
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor() 
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_analytics (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    action_type VARCHAR(20),
                    action_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    details JSON,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing analytics table: {e}")

    def log_action(self, user_id: int, action_type: str, details: Dict = None):
        valid_actions = ['CREATE', 'READ', 'UPDATE', 'DELETE']
        if action_type not in valid_actions:
            raise ValueError(f"Invalid action. Must be one of {valid_actions}")

        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            details_json = json.dumps(details) if details else None

            cursor.execute(
                INSERT INTO user_analytics (user_id, action_type, details) VALUES (%s, %s, %s)''', 
                (user_id, action_type, details_json))

            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error logging action: {e}")

    def get_user_statistics(self, user_id: int) -> Dict:
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor() 
            cursor.execute('''
                SELECT action_type, COUNT(*) as count
                FROM user_analytics
                WHERE user_id = %s
                GROUP BY action_type''', (user_id,))

            results = cursor.fetchall()
            conn.close()

            stats = {
                'CREATE': 0,
                'READ': 0,
                'UPDATE': 0,
                'DELETE': 0,
                'total_operations': 0
            }

            for action_type, count in results:
                stats[action_type] = count
                stats['total_operations'] += count 
            return stats
        except Exception as e:
            print(f"Error retrieving statistics: {e}")
            return {}

    def get_operation_frequency(self, user_id: int, days: int = 30) -> Dict:
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DATE(action_timestamp) as date, 
                       action_type, 
                       COUNT(*) as count
                FROM user_analytics
                WHERE user_id = %s 
                AND action_timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(action_timestamp), action_type
                ORDER BY date DESC''', (user_id, days))

            results = cursor.fetchall()
            conn.close() 
            frequency = {}
            for date, action_type, count in results:
                date_str = str(date)
                if date_str not in frequency:
                    frequency[date_str] = {}
                frequency[date_str][action_type] = count
            return frequency
        except Exception as e:
            print(f"Error retrieving operation frequency: {e}")
            return {}

    def generate_report(self, user_id: int) -> str: 
        stats = self.get_user_statistics(user_id)
        frequency = self.get_operation_frequency(user_id, 30)

        report = f"""
========== USER BEHAVIOR REPORT ==========
User ID: {user_id}
Report Generated: {datetime.now()}

OPERATION STATISTICS (All Time):
- Create Operations: {stats['CREATE']}
- Read Operations: {stats['READ']}
- Update Operations: {stats['UPDATE']}
- Delete Operations: {stats['DELETE']}
- Total Operations: {stats['total_operations']}

OPERATION FREQUENCY (Last 30 Days):
"""
        for date, operations in sorted(frequency.items(), reverse=True):
            report += f"\n{date}:\n"
            for op_type, count in operations.items():
                report += f"  - {op_type}: {count}\n"

        report += "\n========================================\n"
        return report
