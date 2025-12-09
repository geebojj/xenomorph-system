import pandas as pd
from constants import ROLES

def init_sample_data():
    """Initialize all sample dataframes."""
    students_df = pd.DataFrame({
        'student_id': [1, 2, 3],
        'name': ['Alice Johnson', 'Bob Smith', 'Carol Davis'],
        'ssn': ['123-45-6789', '987-65-4321', '456-78-9123'],
        'grades': [85.5, 92.0, 78.5],
        'schedule': ['Math101, Eng102', 'CS201, Math101', 'Bio301, Eng102'],
        'enrollments': ['Fall2025: Math101, Eng102', 'Fall2025: CS201', 'Fall2025: Bio301']
    })
    
    roster_df = pd.DataFrame({
        'course': ['Math101', 'Eng102', 'CS201'],
        'students': [[1, 3], [1, 3], [2]]
    })
    
    payments_df = pd.DataFrame({
        'student_id': [1, 2, 3],
        'amount': [5000.0, 4500.0, 5200.0],
        'status': ['Paid', 'Pending', 'Paid']
    })
    
    assets_df = pd.DataFrame({
        'asset_name': ['Student Records Database', 'Authentication System', 'Grade Management System', 'Course Registration Module', 'Faculty Access Interface', 'Payment/Financial Systems', 'Communication Platform'],
        'type': ['Data', 'Application', 'Application', 'Application', 'Application', 'Data', 'Infrastructure'],
        'value': ['High (PII breach risks fines)', 'High (Bypass enables access)', 'High (Tampering integrity)', 'Medium (Delays recoverable)', 'Medium (RBAC limits abuse)', 'High (Financial loss)', 'Low (Phishing vector)'],
        'owner': ['Registrar', 'IT Dept', 'Faculty/Registrar', 'Registrar', 'IT Dept', 'Finance Dept', 'IT Dept'],
        'security_classification': ['Confidential', 'Restricted', 'Confidential', 'Internal', 'Internal', 'Restricted', 'Public']
    })
    
    threat_matrix = pd.DataFrame({
        'threat': ['Unauthorized Access (FERPA)', 'SQL Injection/Bypass', 'Session Hijacking', 'Data Breaches', 'Insider Threats', 'DDoS Registration'],
        'likelihood': ['High', 'Medium', 'Medium', 'High', 'Medium', 'High'],
        'impact': ['High', 'High', 'Medium', 'High', 'High', 'Medium'],
        'mitigation': ['RBAC Checks', 'Input Validation/Hashing', 'Session Mgmt', 'Encryption', 'RBAC/Logs', 'Rate Limiting']
    })
    
    incident_procedures = pd.DataFrame({
        'scenario': ['Unauthorized Access', 'Data Breach', 'System Downtime', 'Phishing'],
        'detection': ['Log Alerts', 'Anomaly Logs', 'Monitoring', 'User Reports'],
        'response': ['Isolate/Revoke', 'Contain/Assess', 'Failover', 'Quarantine/Educate'],
        'reporting': ['Immediate; 72hrs NPC', '72hrs NPC/Users', '1hr IT', 'Immediate Team'],
        'recovery': ['Re-Train', 'Audit/Enhance', 'Redundancy', 'Campaigns/2FA']
    })
    
    bia_scenarios = pd.DataFrame({
        'scenario': ['Student DB Unavailable Enrollment', 'Grade Tampering', 'Payment Compromise', 'Faculty Access Failure'],
        'impacts': ['Op: Backlog; Fin: ₱2-5M; Rep: Drop; Legal: Fines', 'Op: Disputes; Fin: ₱1M; Rep: Trust; Legal: FERPA', 'Op: Halted; Fin: ₱3-10M; Rep: Media; Legal: RA 10173', 'Op: Delays; Fin: ₱500K; Rep: Minor; Legal: Non-Compliance'],
        'rto_rpo': ['4hrs/1hr', '24hrs/0min', '2hrs/15min', '8hrs/4hrs'],
        'mitigation': ['RBAC/Backups', 'Perms/Logs', 'Roles/Encryption', 'Session/Overrides']
    })
    
    return {
        'students_df': students_df,
        'roster_df': roster_df,
        'payments_df': payments_df,
        'assets_df': assets_df,
        'threat_matrix': threat_matrix,
        'incident_procedures': incident_procedures,
        'bia_scenarios': bia_scenarios
    }

def has_permission(role, perm):
    return perm in ROLES.get(role, [])