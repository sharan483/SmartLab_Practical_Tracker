from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file, abort
)
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
import io

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_here'  # Replace with a strong secret key in production


def init_db():
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            pin TEXT,
            password TEXT,
            role TEXT,
            last_active TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT,
            question TEXT,
            assigned_by TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_email TEXT,
            question_id INTEGER,
            answer_text TEXT,
            timestamp TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            login_time TEXT,
            ip_address TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()


@app.before_request
def update_last_active():
    if 'user' in session and session['user']['role'] == 'student':
        conn = sqlite3.connect('database.db', check_same_thread=False)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE users SET last_active=? WHERE email=?", (now, session['user']['email']))
        conn.commit()
        conn.close()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role')
        pin = request.form.get('pin', '').strip() if role == 'student' else None
        password = request.form.get('password')

        if not all([name, email, role, password]):
            return "All fields are required.", 400
        if role == 'student' and not pin:
            return "PIN is required for students.", 400

        conn = sqlite3.connect('database.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        if cursor.fetchone():
            conn.close()
            return "Email already registered.", 400

        hashed_pw = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (name, email, pin, password, role) VALUES (?, ?, ?, ?, ?)",
            (name, email, pin, hashed_pw, role)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        role = request.form.get('role')
        password = request.form.get('password')

        if role == 'student':
            pin = request.form.get('pin', '').strip()
            if not all([pin, password, role]):
                error = "All fields are required for students."
            else:
                conn = sqlite3.connect('database.db', check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE pin=? AND role='student'", (pin,))
                user = cursor.fetchone()
                conn.close()
                if user and check_password_hash(user[4], password):
                    session['user'] = {
                        'id': user[0], 'name': user[1], 'email': user[2],
                        'pin': user[3], 'role': user[5]
                    }
                    conn = sqlite3.connect('database.db', check_same_thread=False)
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO login_history (user_email, login_time, ip_address) VALUES (?, ?, ?)",
                        (user[2], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr or 'Unknown')
                    )
                    conn.commit()
                    conn.close()
                    return redirect(url_for('student_dashboard'))
                else:
                    error = "Invalid credentials. Please check your entered name/PIN and password."

        elif role == 'teacher':
            name = request.form.get('name', '').strip()
            if not all([name, password, role]):
                error = "All fields are required for teachers."
            else:
                conn = sqlite3.connect('database.db', check_same_thread=False)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE name=? AND role='teacher'", (name,))
                user = cursor.fetchone()
                conn.close()
                if user and check_password_hash(user[4], password):
                    session['user'] = {
                        'id': user[0], 'name': user[1], 'email': user[2],
                        'pin': user[3], 'role': user[5]
                    }
                    conn = sqlite3.connect('database.db', check_same_thread=False)
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO login_history (user_email, login_time, ip_address) VALUES (?, ?, ?)",
                        (user[2], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr or 'Unknown')
                    )
                    conn.commit()
                    conn.close()
                    return redirect(url_for('teacher_dashboard', teacher_name=user[1]))
                else:
                    error = "Invalid credentials. Please check your entered name/PIN and password."
        else:
            error = "Please select a valid role."

    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/student_dashboard')
def student_dashboard():
    if 'user' not in session or session['user']['role'] != 'student':
        return redirect(url_for('login'))
    email = session['user']['email']
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT id, question FROM questions WHERE student_email=? ORDER BY id DESC LIMIT 1", (email,))
    question = cur.fetchone()
    answer_text = ''
    if question:
        cur.execute("SELECT answer_text FROM answers WHERE student_email=? AND question_id=? ORDER BY id DESC LIMIT 1", (email, question[0]))
        ans = cur.fetchone()
        answer_text = ans[0] if ans else ''
    conn.close()
    submitted = request.args.get('submitted') == '1'
    return render_template('student_dashboard.html', 
                           name=session['user']['name'], 
                           pin=session['user']['pin'], 
                           question=question, 
                           answer=answer_text, 
                           submitted=submitted)


@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    if 'user' not in session or session['user']['role'] != 'student':
        return "Unauthorized", 403
    email = session['user']['email']
    question_id = request.form.get('question_id')
    answer_text = request.form.get('answer_text', '').strip()
    if not question_id or not answer_text:
        return "Answer is required.", 400
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO answers (student_email, question_id, answer_text, timestamp) VALUES (?, ?, ?, ?)", 
        (email, question_id, answer_text, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()
    return redirect(url_for('student_dashboard', submitted=1))


@app.route('/teacher_dashboard/<teacher_name>')
def teacher_dashboard(teacher_name):
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    if session['user']['name'] != teacher_name:
        abort(403)
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT pin, email FROM users WHERE role='student' ORDER BY pin")
    students = cur.fetchall()
    cur.execute("SELECT id, student_email, question FROM questions WHERE assigned_by=? ORDER BY id DESC", (teacher_name,))
    assigned_questions = cur.fetchall()
    conn.close()
    return render_template('teacher_dashboard.html', teacher_name=teacher_name, students=students, assigned_questions=assigned_questions)


@app.route('/assign_experiment', methods=['POST'])
def assign_experiment():
    if 'user' not in session or session['user']['role'] != 'teacher':
        return "Unauthorized", 403
    teacher_name = session['user']['name']
    student_email = request.form.get('student_email')
    experiment = request.form.get('experiment')
    if not student_email or not experiment:
        return "All fields are required.", 400
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cur.execute("DELETE FROM questions WHERE student_email=? AND assigned_by=?", (student_email, teacher_name))
    cur.execute("INSERT INTO questions (student_email, question, assigned_by) VALUES (?, ?, ?)", (student_email, experiment, teacher_name))
    conn.commit()
    conn.close()
    return redirect(url_for('teacher_dashboard', teacher_name=teacher_name))


@app.route('/teacher_answers/<student_email>')
def teacher_answers(student_email):
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    teacher_name = session['user']['name']
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cursor_check = cur.execute("SELECT 1 FROM questions WHERE student_email=? AND assigned_by=?", (student_email, teacher_name)).fetchone()
    if not cursor_check:
        conn.close()
        abort(403)
    cur.execute("""
        SELECT a.id, u.name, u.pin, u.email, q.question, a.answer_text, a.timestamp
        FROM answers a
        JOIN questions q ON a.question_id = q.id
        JOIN users u ON a.student_email = u.email
        WHERE a.student_email=? AND q.assigned_by=?
        ORDER BY a.timestamp DESC
    """, (student_email, teacher_name))
    answers = cur.fetchall()
    cur.execute("SELECT name, pin, email FROM users WHERE email=?", (student_email,))
    student = cur.fetchone()
    conn.close()
    return render_template('teacher_answers.html', student=student, answers=answers)


def draw_separator(pdf):
    dash_width = pdf.get_string_width("-")
    max_dashes = max(5, int((pdf.w - pdf.l_margin - pdf.r_margin) / dash_width) - 1)
    pdf.cell(0, 7, "-" * max_dashes, 0, 1)


@app.route('/download_student_answers/<student_email>')
def download_student_answers(student_email):
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    teacher_name = session['user']['name']
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    if not cur.execute("SELECT 1 FROM questions WHERE student_email=? AND assigned_by=?", (student_email, teacher_name)).fetchone():
        conn.close()
        abort(403)
    cur.execute("""
        SELECT q.question, a.answer_text, a.timestamp
        FROM answers a
        JOIN questions q ON a.question_id = q.id
        WHERE a.student_email=? AND q.assigned_by=?
        ORDER BY a.timestamp DESC
    """, (student_email, teacher_name))
    records = cur.fetchall()
    cur.execute("SELECT name, pin, email FROM users WHERE email=?", (student_email,))
    student = cur.fetchone()
    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_font("Arial", 'B', 16)

    if student:
        pdf.cell(0, 10, f"Answers of {student[0]} (PIN: {student[1]})", 0, 1, 'C')
        pdf.cell(0, 10, f"Email: {student[2]}", 0, 1, 'C')
    else:
        pdf.cell(0, 10, "Student not found.", 0, 1, 'C')

    pdf.ln(5)

    if not records:
        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, "No answers found.", 0, 1)
    else:
        for question, answer_text, timestamp in records:
            pdf.set_font("Arial", 'B', 13)
            pdf.cell(0, 7, f"Submitted at: {timestamp}", 0, 1)
            pdf.set_font("Arial", '', 12)
            pdf.multi_cell(0, 7, f"Q: {question or '(No question)'}")
            pdf.multi_cell(0, 7, f"A: {answer_text or '(No answer)'}")
            draw_separator(pdf)

    pdf_output = pdf.output(dest='S')
    pdf_bytes = pdf_output if isinstance(pdf_output, bytes) else pdf_output.encode('latin-1')
    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)

    filename = f"{student[0] if student else student_email}_answers.pdf"
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name=filename)


@app.route('/users')
def users():
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, pin, password, role, last_active FROM users ORDER BY id DESC")
    users = cur.fetchall()
    conn.close()
    return render_template('users.html', users=users)


@app.route('/view_all_answers')
def view_all_answers():
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    teacher_name = session['user']['name']
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT student_email FROM questions WHERE assigned_by=?", (teacher_name,))
    emails = [row[0] for row in cursor.fetchall()]
    answers = []
    if emails:
        placeholders = ','.join('?' for _ in emails)
        query = f"""
            SELECT a.id, u.name, u.pin, u.email, q.question, a.answer_text, a.timestamp
            FROM answers a
            JOIN questions q ON a.question_id = q.id
            JOIN users u ON a.student_email = u.email
            WHERE a.student_email IN ({placeholders})
            ORDER BY a.timestamp DESC
        """
        cursor.execute(query, emails)
        answers = cursor.fetchall()
    conn.close()
    return render_template('view_all_answers.html', answers=answers)


@app.route('/bulk_delete_answers', methods=['POST'])
def bulk_delete_answers():
    if 'user' not in session or session['user']['role'] != 'teacher':
        return jsonify({"error": "Unauthorized"}), 403
    ids = request.json.get('answer_ids', [])
    if not ids:
        return jsonify({"error": "No answers selected."}), 400
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()
    placeholders = ','.join('?' for _ in ids)
    cursor.execute(f"DELETE FROM answers WHERE id IN ({placeholders})", ids)
    conn.commit()
    conn.close()
    return jsonify({"success": True})


@app.route('/download_all_answers')
def download_all_answers():
    if 'user' not in session or session['user']['role'] != 'teacher':
        return redirect(url_for('login'))
    teacher_name = session['user']['name']
    conn = sqlite3.connect('database.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT student_email FROM questions WHERE assigned_by=?", (teacher_name,))
    emails = [row[0] for row in cursor.fetchall()]
    if not emails:
        conn.close()
        return "No answers found.", 404
    placeholders = ','.join('?' for _ in emails)
    query = f"""
        SELECT u.pin, a.answer_text, a.timestamp
        FROM answers a
        JOIN questions q ON a.question_id = q.id
        JOIN users u ON a.student_email = u.email
        WHERE a.student_email IN ({placeholders})
        ORDER BY u.pin, a.timestamp DESC
    """
    cursor.execute(query, emails)
    records = cursor.fetchall()
    conn.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"All Answers for Teacher: {teacher_name}", 0, 1, 'C')
    pdf.ln(5)

    if not records:
        pdf.set_font("Arial", '', 12)
        pdf.cell(0, 10, "No answers found.", 0, 1)
    else:
        last_pin = None
        for pin, answer_text, timestamp in records:
            if pin != last_pin:
                pdf.ln(2)
                pdf.set_font("Arial", 'B', 13)
                pdf.cell(0, 10, f"PIN: {pin}", 0, 1)
                last_pin = pin
            pdf.set_font("Arial", '', 12)
            pdf.multi_cell(0, 7, f"Answer: {answer_text or '(No answer)'}")
            pdf.set_font("Arial", 'I', 11)
            pdf.cell(0, 8, f"Submitted at: {timestamp}", 0, 1)
            # Draw a horizontal line separator (never causes error)
            y = pdf.get_y()
            pdf.set_draw_color(160, 160, 160)
            pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
            pdf.ln(5)

    # This block fixes the AttributeError -- handles both old and new FPDF versions
    pdf_output = pdf.output(dest='S')
    if isinstance(pdf_output, str):
        pdf_bytes = pdf_output.encode('latin1')
    else:
        pdf_bytes = pdf_output  # already bytes/bytearray

    buf = io.BytesIO(pdf_bytes)
    buf.seek(0)
    return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name=f"{teacher_name}_all_answers.pdf")

if __name__ == '__main__':
    app.run(debug=True)
    
    # pip install flask werkzeug fpdf
# python app.py