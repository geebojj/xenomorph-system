from validation import validate_string_input, validate_numeric_input
from utils import log_audit
from database import update_user_active, load_users_df

def student_drop_course(students_df, user, course_to_drop, audit_log):
    """Student: Drop Course (Update enrollments)."""
    sanitized_course, err = validate_string_input(course_to_drop, max_length=20)
    if err:
        return err, audit_log
    users_df = load_users_df()
    user_row = users_df[users_df['username'] == user]
    own_id = user_row['student_id'].iloc[0] if not user_row.empty else None
    own_data = students_df[students_df['student_id'] == own_id]
    if not own_data.empty:
        idx = own_data.index[0]
        current = students_df.at[idx, 'enrollments']
        updated = current.replace(f", {sanitized_course}", "").replace(sanitized_course, "")
        students_df.at[idx, 'enrollments'] = updated.strip(", ")
        audit_log = log_audit(audit_log, user, f"DROP_COURSE: {sanitized_course}")
        return "Dropped!", audit_log
    return "No data found.", audit_log

def faculty_add_to_class(roster_df, course_idx, student_to_add, current_user, audit_log):
    """Faculty: Add Student to Class Roster (Simple update)."""
    valid_student, err = validate_numeric_input(student_to_add, 1, 3)
    if err:
        return err, audit_log
    if 0 <= course_idx < len(roster_df):
        current_students = roster_df.at[course_idx, 'students']
        if valid_student not in current_students:
            current_students.append(valid_student)
            roster_df.at[course_idx, 'students'] = current_students
            roster_df = roster_df.copy()  # Trigger rerun
        audit_log = log_audit(audit_log, current_user, f"ADD_TO_CLASS: Course {course_idx+1} Student {valid_student}")
        return "Added!", audit_log
    return "Invalid course.", audit_log

def registrar_update_payment(payments_df, student_id, new_status, current_user, audit_log):
    """Registrar: Update Payment Status (Simple)."""
    sanitized_status, err = validate_string_input(new_status, max_length=10)
    if err:
        return err, audit_log
    pay_row = payments_df[payments_df['student_id'] == student_id]
    if not pay_row.empty:
        idx = pay_row.index[0]
        payments_df.at[idx, 'status'] = sanitized_status
        audit_log = log_audit(audit_log, current_user, f"UPDATE_PAYMENT: SID{student_id}={sanitized_status}")
        return "Updated!", audit_log
    return "No payment found.", audit_log

def admin_deactivate_user(username_to_deact, current_user, audit_log):
    """Admin: Deactivate User (Simple toggle)."""
    sanitized_u, err = validate_string_input(username_to_deact, max_length=20)
    if err:
        return err, audit_log
    update_user_active(sanitized_u, False)
    users_df = load_users_df()  # Reload for session
    audit_log = log_audit(audit_log, current_user, f"DEACTIVATE_USER: {sanitized_u}")
    return "Deactivated!", audit_log