from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3, os, hashlib
from functools import wraps
from datetime import datetime, timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'hospital.db')

app = Flask(__name__, template_folder=BASE_DIR, static_folder=os.path.join(BASE_DIR, 'static'))
app.secret_key = 'hospital_secret_key_2025'

# ─── DB Helpers ────────────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, '_database', None)
    if db:
        db.close()

def query_db(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def modify_db(sql, args=()):
    db = get_db()
    db.execute(sql, args)
    db.commit()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ─── Init DB ───────────────────────────────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','doctor','patient')),
            is_blacklisted INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            fullname TEXT NOT NULL,
            specialization TEXT NOT NULL,
            department TEXT NOT NULL,
            experience INTEGER DEFAULT 0,
            bio TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            fullname TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            overview TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS availability (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
            slot_date TEXT NOT NULL,
            morning_start TEXT DEFAULT '08:00',
            morning_end TEXT DEFAULT '12:00',
            evening_start TEXT DEFAULT '16:00',
            evening_end TEXT DEFAULT '21:00',
            UNIQUE(doctor_id, slot_date)
        );
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
            doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
            slot_date TEXT NOT NULL,
            time_slot TEXT NOT NULL,
            status TEXT DEFAULT 'upcoming' CHECK(status IN ('upcoming','completed','cancelled')),
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS patient_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
            doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
            appointment_id INTEGER REFERENCES appointments(id),
            visit_type TEXT DEFAULT 'In-person',
            tests_done TEXT DEFAULT '',
            diagnosis TEXT DEFAULT '',
            prescription TEXT DEFAULT '',
            medicines TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
    ''')
    # Seed admin if not exists
    admin = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
                   ('admin', hash_pw('admin123')))
        db.commit()
    # Seed departments
    for dept in ['Cardiology', 'Oncology', 'General', 'Neurology', 'Orthopedics']:
        db.execute("INSERT OR IGNORE INTO departments (name, overview) VALUES (?, ?)",
                   (dept, f'The {dept} department provides comprehensive care.'))
    db.commit()
    db.close()

# ─── Auth Decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') not in roles:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Auth Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for(session['role'] + '_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        user = query_db("SELECT * FROM users WHERE username=? AND password=?",
                        (request.form['username'], hash_pw(request.form['password'])), one=True)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for(user['role'] + '_dashboard'))
        flash('Invalid credentials. Please try again.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        fullname = request.form.get('fullname','')
        existing = query_db("SELECT id FROM users WHERE username=?", (uname,), one=True)
        if existing:
            flash('Username already taken.', 'error')
            return render_template('register.html')
        try:
            db = get_db()
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'patient')",
                       (uname, hash_pw(pw)))
            db.commit()
            user = query_db("SELECT id FROM users WHERE username=?", (uname,), one=True)
            db.execute("INSERT INTO patients (user_id, fullname) VALUES (?, ?)",
                       (user['id'], fullname or uname))
            db.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Registration failed.', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ─── Admin Routes ──────────────────────────────────────────────────────────────
@app.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    doctors = query_db('''
        SELECT u.id, u.username, u.is_blacklisted, d.fullname, d.specialization, d.department
        FROM users u JOIN doctors d ON u.id=d.user_id ORDER BY d.fullname
    ''')
    patients = query_db('''
        SELECT u.id, u.username, u.is_blacklisted, p.fullname
        FROM users u JOIN patients p ON u.id=p.user_id ORDER BY p.fullname
    ''')
    appointments = query_db('''
        SELECT a.id, p.fullname as patient_name, d.fullname as doctor_name,
               doc.department, a.slot_date, a.status, a.id as appt_id
        FROM appointments a
        JOIN patients p ON a.patient_id=p.id
        JOIN doctors d ON a.doctor_id=d.id
        JOIN doctors doc ON a.doctor_id=doc.id
        ORDER BY a.slot_date DESC LIMIT 20
    ''')
    search = request.args.get('q','')
    if search:
        doctors = query_db('''
            SELECT u.id, u.username, u.is_blacklisted, d.fullname, d.specialization, d.department
            FROM users u JOIN doctors d ON u.id=d.user_id
            WHERE d.fullname LIKE ? OR d.department LIKE ? OR d.specialization LIKE ?
        ''', (f'%{search}%', f'%{search}%', f'%{search}%'))
        patients = query_db('''
            SELECT u.id, u.username, u.is_blacklisted, p.fullname
            FROM users u JOIN patients p ON u.id=p.user_id
            WHERE p.fullname LIKE ? OR u.username LIKE ?
        ''', (f'%{search}%', f'%{search}%'))
    return render_template('admin_dashboard.html', doctors=doctors, patients=patients,
                           appointments=appointments, search=search)

@app.route('/admin/add_doctor', methods=['GET','POST'])
@login_required
@role_required('admin')
def add_doctor():
    departments = query_db("SELECT name FROM departments ORDER BY name")
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        fullname = request.form['fullname']
        spec = request.form['specialization']
        dept = request.form['department']
        exp = request.form.get('experience', 0)
        bio = request.form.get('bio', '')
        existing = query_db("SELECT id FROM users WHERE username=?", (uname,), one=True)
        if existing:
            flash('Username already taken.', 'error')
            return render_template('add_doctor.html', departments=departments)
        try:
            db = get_db()
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'doctor')",
                       (uname, hash_pw(pw)))
            db.commit()
            user = query_db("SELECT id FROM users WHERE username=?", (uname,), one=True)
            db.execute("INSERT INTO doctors (user_id, fullname, specialization, department, experience, bio) VALUES (?, ?, ?, ?, ?, ?)",
                       (user['id'], fullname, spec, dept, exp, bio))
            db.commit()
            flash(f'Dr. {fullname} added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash('Failed to add doctor.', 'error')
    return render_template('add_doctor.html', departments=departments)

@app.route('/admin/delete_doctor/<int:uid>', methods=['POST'])
@login_required
@role_required('admin')
def delete_doctor(uid):
    modify_db("DELETE FROM users WHERE id=?", (uid,))
    flash('Doctor removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_patient/<int:uid>', methods=['POST'])
@login_required
@role_required('admin')
def delete_patient(uid):
    modify_db("DELETE FROM users WHERE id=?", (uid,))
    flash('Patient removed.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/view_history/<int:patient_id>')
@login_required
@role_required('admin')
def admin_view_history(patient_id):
    patient = query_db("SELECT * FROM patients WHERE id=?", (patient_id,), one=True)
    history = query_db('''
        SELECT ph.*, d.fullname as doctor_name, d.department
        FROM patient_history ph
        JOIN doctors d ON ph.doctor_id=d.id
        WHERE ph.patient_id=? ORDER BY ph.created_at DESC
    ''', (patient_id,))
    return render_template('patient_history.html', patient=patient, history=history, viewer='admin')

# ─── Doctor Routes ─────────────────────────────────────────────────────────────
@app.route('/doctor')
@login_required
@role_required('doctor')
def doctor_dashboard():
    doc = query_db("SELECT * FROM doctors WHERE user_id=?", (session['user_id'],), one=True)
    appointments = query_db('''
        SELECT a.*, p.fullname as patient_name
        FROM appointments a JOIN patients p ON a.patient_id=p.id
        WHERE a.doctor_id=? AND a.status='upcoming'
        ORDER BY a.slot_date, a.time_slot
    ''', (doc['id'],))
    assigned_patients = query_db('''
        SELECT DISTINCT p.id, p.fullname, u.username
        FROM patients p JOIN users u ON p.user_id=u.id
        JOIN appointments a ON a.patient_id=p.id
        WHERE a.doctor_id=?
        ORDER BY p.fullname
    ''', (doc['id'],))
    return render_template('doctor_dashboard.html', doc=doc, appointments=appointments,
                           assigned_patients=assigned_patients)

@app.route('/doctor/availability', methods=['GET','POST'])
@login_required
@role_required('doctor')
def set_availability():
    doc = query_db("SELECT * FROM doctors WHERE user_id=?", (session['user_id'],), one=True)
    if request.method == 'POST':
        db = get_db()
        for i in range(7):
            d = request.form.get(f'date_{i}')
            if d:
                ms = request.form.get(f'morning_start_{i}', '08:00')
                me = request.form.get(f'morning_end_{i}', '12:00')
                es = request.form.get(f'evening_start_{i}', '16:00')
                ee = request.form.get(f'evening_end_{i}', '21:00')
                db.execute('''INSERT INTO availability (doctor_id, slot_date, morning_start, morning_end, evening_start, evening_end)
                              VALUES (?,?,?,?,?,?)
                              ON CONFLICT(doctor_id,slot_date) DO UPDATE SET
                              morning_start=excluded.morning_start, morning_end=excluded.morning_end,
                              evening_start=excluded.evening_start, evening_end=excluded.evening_end''',
                           (doc['id'], d, ms, me, es, ee))
        db.commit()
        flash('Availability saved!', 'success')
        return redirect(url_for('set_availability'))
    # Generate next 7 days
    slots = []
    today = datetime.today()
    for i in range(7):
        day = today + timedelta(days=i)
        d = day.strftime('%Y-%m-%d')
        existing = query_db("SELECT * FROM availability WHERE doctor_id=? AND slot_date=?",
                            (doc['id'], d), one=True)
        slots.append({'date': d, 'label': day.strftime('%d/%m/%Y'), 'data': existing})
    return render_template('set_availability.html', doc=doc, slots=slots)

@app.route('/doctor/patient/<int:patient_id>')
@login_required
@role_required('doctor')
def view_patient(patient_id):
    doc = query_db("SELECT * FROM doctors WHERE user_id=?", (session['user_id'],), one=True)
    patient = query_db("SELECT * FROM patients WHERE id=?", (patient_id,), one=True)
    history = query_db('''
        SELECT ph.*, d.fullname as doctor_name, d.department
        FROM patient_history ph JOIN doctors d ON ph.doctor_id=d.id
        WHERE ph.patient_id=? ORDER BY ph.created_at DESC
    ''', (patient_id,))
    appointments = query_db('''
        SELECT * FROM appointments WHERE patient_id=? AND doctor_id=?
        ORDER BY slot_date DESC
    ''', (patient_id, doc['id']))
    return render_template('doctor_view_patient.html', patient=patient, history=history,
                           appointments=appointments, doc=doc)

@app.route('/doctor/update_history/<int:appointment_id>', methods=['GET','POST'])
@login_required
@role_required('doctor')
def update_history(appointment_id):
    doc = query_db("SELECT * FROM doctors WHERE user_id=?", (session['user_id'],), one=True)
    appt = query_db("SELECT a.*, p.fullname as patient_name, p.id as pid FROM appointments a JOIN patients p ON a.patient_id=p.id WHERE a.id=?",
                    (appointment_id,), one=True)
    existing = query_db("SELECT * FROM patient_history WHERE appointment_id=?", (appointment_id,), one=True)
    if request.method == 'POST':
        vtype = request.form.get('visit_type','In-person')
        tests = request.form.get('tests_done','')
        diag = request.form.get('diagnosis','')
        presc = request.form.get('prescription','')
        meds = request.form.get('medicines','')
        db = get_db()
        if existing:
            db.execute('''UPDATE patient_history SET visit_type=?,tests_done=?,diagnosis=?,prescription=?,medicines=?
                          WHERE appointment_id=?''', (vtype, tests, diag, presc, meds, appointment_id))
        else:
            db.execute('''INSERT INTO patient_history (patient_id,doctor_id,appointment_id,visit_type,tests_done,diagnosis,prescription,medicines)
                          VALUES (?,?,?,?,?,?,?,?)''',
                       (appt['pid'], doc['id'], appointment_id, vtype, tests, diag, presc, meds))
        db.execute("UPDATE appointments SET status='completed' WHERE id=?", (appointment_id,))
        db.commit()
        flash('Patient history updated!', 'success')
        return redirect(url_for('doctor_dashboard'))
    return render_template('update_history.html', appt=appt, doc=doc, existing=existing)

# ─── Patient Routes ────────────────────────────────────────────────────────────
@app.route('/patient')
@login_required
@role_required('patient')
def patient_dashboard():
    pat = query_db("SELECT * FROM patients WHERE user_id=?", (session['user_id'],), one=True)
    departments = query_db("SELECT * FROM departments ORDER BY name")
    appointments = query_db('''
        SELECT a.*, d.fullname as doctor_name, doc.department
        FROM appointments a JOIN doctors d ON a.doctor_id=d.id
        JOIN doctors doc ON a.doctor_id=doc.id
        WHERE a.patient_id=? AND a.status='upcoming'
        ORDER BY a.slot_date
    ''', (pat['id'],))
    return render_template('patient_dashboard.html', pat=pat, departments=departments,
                           appointments=appointments)

@app.route('/patient/department/<int:dept_id>')
@login_required
@role_required('patient')
def view_department(dept_id):
    dept = query_db("SELECT * FROM departments WHERE id=?", (dept_id,), one=True)
    doctors = query_db("SELECT * FROM doctors WHERE department=? ORDER BY fullname", (dept['name'],))
    return render_template('view_department.html', dept=dept, doctors=doctors)

@app.route('/patient/doctor/<int:doctor_id>')
@login_required
@role_required('patient')
def view_doctor(doctor_id):
    doc = query_db("SELECT * FROM doctors WHERE id=?", (doctor_id,), one=True)
    availability = query_db('''
        SELECT * FROM availability WHERE doctor_id=? AND slot_date >= date('now')
        ORDER BY slot_date LIMIT 7
    ''', (doctor_id,))
    return render_template('view_doctor.html', doc=doc, availability=availability)

@app.route('/patient/book/<int:doctor_id>/<string:slot_date>/<string:time_slot>', methods=['POST'])
@login_required
@role_required('patient')
def book_appointment(doctor_id, slot_date, time_slot):
    pat = query_db("SELECT * FROM patients WHERE user_id=?", (session['user_id'],), one=True)
    existing = query_db('''SELECT id FROM appointments WHERE patient_id=? AND doctor_id=? AND slot_date=? AND status='upcoming' ''',
                        (pat['id'], doctor_id, slot_date), one=True)
    if existing:
        flash('You already have an appointment with this doctor on that date.', 'error')
    else:
        modify_db("INSERT INTO appointments (patient_id, doctor_id, slot_date, time_slot) VALUES (?,?,?,?)",
                  (pat['id'], doctor_id, slot_date, time_slot))
        flash('Appointment booked successfully!', 'success')
    return redirect(url_for('patient_dashboard'))

@app.route('/patient/history')
@login_required
@role_required('patient')
def patient_history():
    pat = query_db("SELECT * FROM patients WHERE user_id=?", (session['user_id'],), one=True)
    history = query_db('''
        SELECT ph.*, d.fullname as doctor_name, d.department
        FROM patient_history ph JOIN doctors d ON ph.doctor_id=d.id
        WHERE ph.patient_id=? ORDER BY ph.created_at DESC
    ''', (pat['id'],))
    return render_template('patient_history.html', patient=pat, history=history, viewer='patient')

@app.route('/patient/edit_profile', methods=['GET','POST'])
@login_required
@role_required('patient')
def edit_profile():
    pat = query_db("SELECT * FROM patients WHERE user_id=?", (session['user_id'],), one=True)
    if request.method == 'POST':
        fullname = request.form.get('fullname', pat['fullname'])
        modify_db("UPDATE patients SET fullname=? WHERE user_id=?", (fullname, session['user_id']))
        flash('Profile updated!', 'success')
        return redirect(url_for('patient_dashboard'))
    return render_template('edit_profile.html', pat=pat)

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    else:
        with app.app_context():
            init_db()
    app.run(debug=True)