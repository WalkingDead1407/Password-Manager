import mysql.connector
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict
import statistics

class BehaviorAnalytics:
    def __init__(self, db_config: Dict):
        self.db_config = db_config

    def get_peak_usage_times(self, user_id: int, days: int = 30) -> Dict:
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT HOUR(action_timestamp) as hour, 
                       COUNT(*) as count
                FROM user_analytics
                WHERE user_id = %s 
                AND action_timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY HOUR(action_timestamp)
                ORDER BY count DESC''', (user_id, days))
            results = cursor.fetchall()
            conn.close()

            peak_times = {}
            for hour, count in results:
                peak_times[f"{hour:02d}:00"] = count
            return peak_times
        except Exception as e:
            print(f"Error: {e}")
            return {}

    def get_password_distribution(self, user_id: int) -> Dict:
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT website, COUNT(*) as count
                FROM passwords
                WHERE user_id = %s
                GROUP BY website
                ORDER BY count DESC''', (user_id,))
            results = cursor.fetchall()
            conn.close()
            distribution = {}
            for website, count in results:
                distribution[website] = count
            return distribution
        except Exception as e:
            print(f"Error: {e}")
            return {}

    def get_operation_trends(self, user_id: int, days: int = 30) -> Dict:
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
                ORDER BY date, action_type
            ''', (user_id, days))
            results = cursor.fetchall()
            conn.close()

            trends = defaultdict(lambda: defaultdict(int))
            for date, action_type, count in results:
                trends[str(date)][action_type] = count
            return dict(trends)
        except Exception as e:
            print(f"Error: {e}")
            return {}

    def get_user_risk_profile(self, user_id: int) -> Dict:
        try:
            conn = mysql.connector.connect(**self.db_config)
            cursor = conn.cursor()

            risk_score = 0
            risk_factors = []

            # Check for excessive delete operations
            cursor.execute('''
                SELECT COUNT(*) FROM user_analytics
                WHERE user_id = %s 
                AND action_type = 'DELETE'
                AND action_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''', (user_id,))

            recent_deletes = cursor.fetchone()[0]
            if recent_deletes > 10:
                risk_score += 20
                risk_factors.append("Excessive password deletions in last 7 days")

            # Check for many failed attempts (READ operations with no passwords stored)
            cursor.execute('''
                SELECT COUNT(DISTINCT action_timestamp) 
                FROM user_analytics
                WHERE user_id = %s 
                AND action_type = 'READ'
                AND action_timestamp >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            ''', (user_id,))

            read_attempts = cursor.fetchone()[0]
            if read_attempts > 20:
                risk_score += 15
                risk_factors.append("High number of read attempts in last 24 hours")

            # Check if no backups (creates) but multiple deletes
            cursor.execute('''
                SELECT COUNT(*) FROM user_analytics
                WHERE user_id = %s 
                AND action_type = 'CREATE'
                AND action_timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            ''', (user_id,))

            recent_creates = cursor.fetchone()[0]
            if recent_creates == 0 and recent_deletes > 5:
                risk_score += 25
                risk_factors.append("No new passwords added while deleting existing ones")
            conn.close()

            risk_level = "Low"
            if risk_score >= 50:
                risk_level = "High"
            elif risk_score >= 25:
                risk_level = "Medium"
            return {
                'risk_score': risk_score,
                'risk_level': risk_level,
                'factors': risk_factors
            }
        except Exception as e:
            print(f"Error: {e}")
            return {}
    def generate_behavior_report(self, user_id: int) -> str:
        peak_times = self.get_peak_usage_times(user_id)
        distribution = self.get_password_distribution(user_id)
        trends = self.get_operation_trends(user_id)
        risk = self.get_user_risk_profile(user_id) 
        report = f"""
╔════════════════════════════════════════════════════════════╗
║       USER BEHAVIOR ANALYSIS REPORT
║       User ID: {user_id}
║       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚════════════════════════════════════════════════════════════╝

PEAK USAGE TIMES (Last 30 days):
"""
        if peak_times:
            for time, count in sorted(peak_times.items(), key=lambda x: x[1], reverse=True)[:5]:
                report += f"  {time} - {count} operations\n"
        else:
            report += "  No data available\n"

        report += f"\nPASSWORD DISTRIBUTION:
  Total Passwords Stored: {len(distribution)}
"""
        for website, count in sorted(distribution.items(), key=lambda x: x[1], reverse=True)[:5]:
            report += f"  - {website}: {count}\n"

        report += f"\nRECENT TRENDS (Last 7 days):
"""
        if trends:
            for date in sorted(trends.keys(), reverse=True)[:7]:
                report += f"  {date}:\n"
                for action, count in trends[date].items():
                    report += f"    - {action}: {count}\n"
        else:
            report += "  No data available\n"

        report += f"\nSECURITY RISK ASSESSMENT:
  Risk Score: {risk.get('risk_score', 0)}/100
  Risk Level: {risk.get('risk_level', 'Unknown')}
  Risk Factors:\n"
        for factor in risk.get('factors', []):
            report += f"    ⚠ {factor}\n"

        report += "\n════════════════════════════════════════════════════════════\n"
        return report
