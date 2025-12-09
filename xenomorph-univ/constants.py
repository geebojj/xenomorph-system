# Constants for the University Portal Demo

DB_FILE = 'xenomorph.db'

ROLES = {
    'student': ['view_own_grades', 'view_schedule', 'register_courses', 'drop_course'],
    'faculty': ['view_class_roster', 'input_grades', 'view_student_info', 'add_to_class'],
    'registrar': ['view_all_records', 'modify_enrollment', 'generate_reports', 'update_payment', 'view_all_users'],
    'admin': ['manage_users', 'system_config', 'view_audit_logs', 'deactivate_user']
}

SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
PASSWORD_MIN_LENGTH = 6
USERNAME_MAX_LENGTH = 20
STRING_INPUT_MAX_LENGTH = 50
GRADE_MIN_VAL = 0
GRADE_MAX_VAL = 100