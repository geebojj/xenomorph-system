import streamlit as st
import pandas as pd
import datetime
from database import init_db, load_users_df, save_user
from auth import login, register_user, hash_password
from data import init_sample_data, has_permission
from utils import check_session_timeout, log_audit, encrypt_sensitive
from components import school_profile, upload_visual_diagram, sql_editor, crypto_demo
from roles import student_drop_course, faculty_add_to_class, registrar_update_payment, admin_deactivate_user
from constants import ROLES
from validation import validate_string_input, validate_numeric_input, validate_password  # Added validate_password

# Session State Initialization
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'current_role' not in st.session_state:
    st.session_state.current_role = None
if 'login_time' not in st.session_state:
    st.session_state.login_time = None
if 'consent_given' not in st.session_state:
    st.session_state.consent_given = False
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = pd.DataFrame(columns=['timestamp', 'user', 'action'])

# Initialize DB and load data
init_db()
if 'users_df' not in st.session_state:
    st.session_state.users_df = load_users_df()

# Initialize sample data
sample_data = init_sample_data()
for key, df in sample_data.items():
    if key not in st.session_state:
        st.session_state[key] = df

def logout():
    if st.session_state.current_user:
        st.session_state.audit_log = log_audit(st.session_state.audit_log, st.session_state.current_user, "LOGOUT")
    for key in ['logged_in', 'current_user', 'current_role', 'login_time', 'consent_given']:
        del st.session_state[key]
    st.rerun()

# Main App
st.title("XENOMORPH UNIVERSITY PORTAL")

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])

    with tab1:
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            consent = st.checkbox("Consent per RA 10173/FERPA")
            if st.form_submit_button("Login"):
                success, result = login(username, password, consent)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.current_user = result['username']
                    st.session_state.current_role = result['role']
                    st.session_state.login_time = datetime.datetime.now()
                    st.session_state.consent_given = True
                    st.session_state.users_df = load_users_df()  # Reload
                    st.session_state.audit_log = log_audit(st.session_state.audit_log, result['username'], f"LOGIN: {result['role']}")
                    st.success(f"Welcome {result['username']} ({result['role']})")
                    st.rerun()
                else:
                    st.error(result)
                    st.session_state.audit_log = log_audit(st.session_state.audit_log, username or 'UNKNOWN', "LOGIN_FAIL")

    with tab2:
        st.header("Registration Form (New User Signup)")
        with st.form("register_form"):
            reg_username = st.text_input("New Username")
            reg_password = st.text_input("New Password", type="password")
            reg_role = st.selectbox("Role", ['student'])  # Demo: Auto student
            reg_consent = st.checkbox("Consent per RA 10173/FERPA for registration")
            if st.form_submit_button("Register"):
                student_id = None
                if reg_role == 'student':
                    student_id = len(st.session_state.students_df) + 1
                    # Append dummy row for new student to students_df
                    new_student_row = pd.DataFrame({
                        'student_id': [student_id],
                        'name': [reg_username.capitalize() + ' Student'],
                        'ssn': ['XXX-XX-XXXX'],  # Dummy for demo
                        'grades': [0.0],
                        'schedule': [''],
                        'enrollments': ['']
                    })
                    st.session_state.students_df = pd.concat([st.session_state.students_df, new_student_row], ignore_index=True)
                success, result = register_user(reg_username, reg_password, reg_role, student_id=student_id)
                if success:
                    st.session_state.users_df = load_users_df()  # Reload
                    st.success(result)
                else:
                    st.error(result)
else:
    if check_session_timeout(st.session_state.login_time):
        logout()
        st.warning("Session timed out")
        st.stop()
    
    role = st.session_state.current_role
    user = st.session_state.current_user
    st.sidebar.success(f"{user} ({role})")
    if st.sidebar.button("Logout"):
        logout()
    st.header(f"{role.title()} Dashboard")

    # School Profile Feature (Accessible to all roles)
    with st.expander("School Profile"):
        school_profile()

    # Controls Info
    st.info("**Controls:** RBAC, bcrypt hash, encrypt fields, session mgmt, audit logs, input validation (string/numeric sanitization). Mitigates threats (e.g., unauthorized via checks). Trade-off: Security > Usability.")

    # Role Dashboards
    if role == 'student':
        user_row = st.session_state.users_df[st.session_state.users_df['username'] == user]
        own_id = user_row['student_id'].iloc[0] if not user_row.empty else None
        own_data = st.session_state.students_df[st.session_state.students_df['student_id'] == own_id]
        if has_permission(role, 'view_own_grades'):
            st.subheader("Grades")
            if not own_data.empty:
                st.metric("GPA", own_data['grades'].iloc[0])
                st.write("Encrypted SSN:", encrypt_sensitive(own_data['ssn'].iloc[0]))
        if has_permission(role, 'view_schedule'):
            st.subheader("Schedule")
            if not own_data.empty:
                st.write(own_data['schedule'].iloc[0])
        if has_permission(role, 'register_courses'):
            st.subheader("Register")
            course = st.text_input("Course Name")
            if st.button("Register"):
                sanitized_course, err = validate_string_input(course, max_length=20)
                if err:
                    st.error(err)
                else:
                    if not own_data.empty:
                        idx = own_data.index[0]
                        current = st.session_state.students_df.at[idx, 'enrollments']
                        st.session_state.students_df.at[idx, 'enrollments'] = f"{current}, {sanitized_course}"
                        st.session_state.audit_log = log_audit(st.session_state.audit_log, user, f"REGISTER: {sanitized_course}")
                        st.success("Registered!")
        # Additional Function
        if has_permission(role, 'drop_course'):
            st.subheader("Drop Course")
            course_to_drop = st.text_input("Course to Drop")
            if st.button("Drop"):
                msg, st.session_state.audit_log = student_drop_course(st.session_state.students_df, user, course_to_drop, st.session_state.audit_log)
                if "Dropped" in msg:
                    st.success(msg)
                else:
                    st.error(msg)

    elif role == 'faculty':
        if has_permission(role, 'view_class_roster'):
            st.subheader("Roster")
            st.dataframe(st.session_state.roster_df)
        if has_permission(role, 'input_grades'):
            st.subheader("Input Grades")
            sid = st.number_input("Student ID", 1, 3, key="input_grades_sid")
            grade_input = st.number_input("Grade", 0.0, 100.0, key="input_grades_grade")
            if st.button("Submit"):
                valid_grade, err = validate_numeric_input(grade_input, 0, 100)
                if err:
                    st.error(err)
                else:
                    sid_df = st.session_state.students_df[st.session_state.students_df['student_id'] == sid]
                    if not sid_df.empty:
                        idx = sid_df.index[0]
                        st.session_state.students_df.at[idx, 'grades'] = valid_grade
                        st.session_state.audit_log = log_audit(st.session_state.audit_log, user, f"GRADE: {sid}={valid_grade}")
                        st.success("Submitted!")
        if has_permission(role, 'view_student_info'):
            st.subheader("Student Info")
            sid = st.selectbox("Student ID", [1,2,3])
            data = st.session_state.students_df[st.session_state.students_df['student_id'] == sid]
            st.dataframe(data)
            if not data.empty:
                st.write("Encrypted SSN:", encrypt_sensitive(data['ssn'].iloc[0]))
        # Additional Function
        if has_permission(role, 'add_to_class'):
            st.subheader("Add to Class")
            course_idx = st.selectbox("Course Index", [0,1,2])
            student_to_add = st.number_input("Student ID to Add", 1, 3, key="add_to_class_student")
            if st.button("Add"):
                msg, st.session_state.audit_log = faculty_add_to_class(st.session_state.roster_df, course_idx, student_to_add, user, st.session_state.audit_log)
                if "Added" in msg:
                    st.success(msg)
                else:
                    st.error(msg)

    elif role == 'registrar':
        if has_permission(role, 'view_all_records'):
            st.subheader("All Student Records")
            st.dataframe(st.session_state.students_df)
        if has_permission(role, 'view_all_users'):
            st.subheader("All Registered Users")
            st.dataframe(st.session_state.users_df[['username', 'role', 'student_id', 'active']])  # Hide password_hash
        if has_permission(role, 'modify_enrollment'):
            st.subheader("Modify Enrollment")
            sid = st.number_input("Student ID", 1, 3, key="modify_enrollment_sid")
            new_en = st.text_input("Enrollment")
            if st.button("Modify"):
                sanitized_en, err = validate_string_input(new_en, max_length=100)
                if err:
                    st.error(err)
                else:
                    sid_df = st.session_state.students_df[st.session_state.students_df['student_id'] == sid]
                    if not sid_df.empty:
                        idx = sid_df.index[0]
                        st.session_state.students_df.at[idx, 'enrollments'] = sanitized_en
                        st.session_state.audit_log = log_audit(st.session_state.audit_log, user, f"ENROLL: {sid}={sanitized_en}")
                        st.success("Modified!")
        if has_permission(role, 'generate_reports'):
            st.subheader("Reports")
            if st.button("Generate"):
                st.session_state.audit_log = log_audit(st.session_state.audit_log, user, "REPORT")
                st.dataframe(st.session_state.students_df.describe())
        st.subheader("Payments")
        st.dataframe(st.session_state.payments_df)
        if st.button("Process Pending"):
            pending = st.session_state.payments_df['status'] == 'Pending'
            st.session_state.payments_df.loc[pending, 'status'] = 'Paid'
            st.session_state.audit_log = log_audit(st.session_state.audit_log, user, "PAYMENTS")
            st.success("Processed!")
        # Additional Function
        if has_permission(role, 'update_payment'):
            st.subheader("Update Payment Status")
            sid = st.number_input("Student ID", 1, 3, key="update_payment_sid")
            new_status = st.text_input("New Status (e.g., Paid/Pending)")
            if st.button("Update"):
                msg, st.session_state.audit_log = registrar_update_payment(st.session_state.payments_df, sid, new_status, user, st.session_state.audit_log)
                if "Updated" in msg:
                    st.success(msg)
                else:
                    st.error(msg)

    elif role == 'admin':
        with st.expander("Visual Representations (Text Descriptions)"):
            st.markdown("""
**System Architecture:** Browser (Streamlit UI) → Login (bcrypt Hash) → RBAC Check → Role-Specific Data (Pandas Assets) → Audit Log → Session Mgmt.
**Data Flow:** User Login → Role Verify → Perm Check → Filtered Data (Encrypted SSN) → Log Action → Update Session.
**RBAC Permission Matrix:** Student: view_own_grades/view_schedule/register_courses/drop_course ✓; Faculty: view_class_roster/input_grades/view_student_info/add_to_class ✓; Registrar: view_all_records/modify_enrollment/generate_reports/update_payment/view_all_users ✓; Admin: manage_users/system_config/view_audit_logs/deactivate_user ✓.
**Incident Response Flowchart:** Detect Incident → Triage (High/Med/Low) → Contain/Revoke RBAC → Report (72hrs NPC) → Recover/Train → Close.
            """)
            # Integrated file upload
            st.session_state.audit_log = upload_visual_diagram(user, st.session_state.audit_log)
        
        with st.expander("Assets"):
            edited = st.data_editor(st.session_state.assets_df)
            if st.button("Export"):
                csv, filename = edited.streamlit_export("assets.csv")
                st.session_state.audit_log = log_audit(st.session_state.audit_log, user, f"EXPORT: {filename}")
                st.download_button("Download", csv, filename)
        
        with st.expander("Threats"):
            st.dataframe(st.session_state.threat_matrix)
        with st.expander("Incidents"):
            st.dataframe(st.session_state.incident_procedures)
        with st.expander("BIA"):
            st.dataframe(st.session_state.bia_scenarios)
            scenario = st.selectbox("Scenario", st.session_state.bia_scenarios['scenario'])
            if st.button("Simulate"):
                row = st.session_state.bia_scenarios[st.session_state.bia_scenarios['scenario'] == scenario].iloc[0]
                st.write(f"Impacts: {row['impacts']}")
                st.session_state.audit_log = log_audit(st.session_state.audit_log, user, "BIA")
        
        # Crypto Demo
        with st.expander("Crypto Demo: Hashing (bcrypt) and XOR (Simple Cipher)"):
            crypto_demo()
        
        # SQL Editor
        with st.expander("SQL Editor"):
            st.session_state.audit_log = sql_editor(user, st.session_state.audit_log)
        
        if has_permission(role, 'manage_users'):
            st.subheader("Manage Users")
            new_u = st.text_input("New User")
            new_p = st.text_input("Pw", type="password")
            new_r = st.selectbox("Role", list(ROLES.keys()))
            if st.button("Add"):
                sanitized_u, u_err = validate_string_input(new_u, max_length=20)
                if u_err:
                    st.error(u_err)
                else:
                    pw_valid, p_err = validate_password(new_p)
                    if not pw_valid:
                        st.error(p_err)
                    else:
                        new_h = hash_password(new_p)
                        new_row = {'username': sanitized_u, 'password_hash': new_h, 'role': new_r, 'student_id': None, 'active': True}
                        save_user(new_row)
                        st.session_state.users_df = load_users_df()
                        st.session_state.audit_log = log_audit(st.session_state.audit_log, user, "ADD_USER")
                        st.success("Added!")
            # Additional Function
            if has_permission(role, 'deactivate_user'):
                st.subheader("Deactivate User")
                username_to_deact = st.text_input("Username to Deactivate")
                if st.button("Deactivate"):
                    msg, st.session_state.audit_log = admin_deactivate_user(username_to_deact, user, st.session_state.audit_log)
                    if "Deactivated" in msg:
                        st.session_state.users_df = load_users_df()
                        st.success(msg)
                    else:
                        st.error(msg)
        if has_permission(role, 'view_audit_logs'):
            st.subheader("Logs")
            st.dataframe(st.session_state.audit_log)