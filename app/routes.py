from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from app.models import User, ScanTarget, ComplianceCheck, RemediationTask
from app.scanner import PCIScanner
from app.report import generate_pdf_report
from datetime import datetime
import os
import re

main = Blueprint('main', __name__)


# ── USER LOADER ──
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── REGISTER ──
@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username         = request.form.get('username').strip()
        email            = request.form.get('email').strip()
        password         = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('main.register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.')
            return redirect(url_for('main.register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('main.register'))

        new_user = User(
            username = username,
            email    = email,
            password = generate_password_hash(password),
            role     = 'user'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please login.')
        return redirect(url_for('main.login'))

    return render_template('register.html')




# ── LOGIN ──
@main.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            # Redirect admin to admin dashboard
            if user.role == 'admin':
                return redirect(url_for('main.admin_dashboard'))
            return redirect(url_for('main.dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html')



# ── LOGOUT ──
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


# ── DASHBOARD ──
@main.route('/dashboard')
@login_required
def dashboard():
    # Only show THIS user's targets and results
    targets = ScanTarget.query.filter_by(user_id=current_user.id).all()

    user_target_ids = [t.id for t in targets]

    if user_target_ids:
        total_checks  = ComplianceCheck.query.filter(
            ComplianceCheck.target_id.in_(user_target_ids)).count()
        total_passed  = ComplianceCheck.query.filter(
            ComplianceCheck.target_id.in_(user_target_ids),
            ComplianceCheck.status == 'PASS').count()
        total_failed  = ComplianceCheck.query.filter(
            ComplianceCheck.target_id.in_(user_target_ids),
            ComplianceCheck.status == 'FAIL').count()
        total_warning = ComplianceCheck.query.filter(
            ComplianceCheck.target_id.in_(user_target_ids),
            ComplianceCheck.status == 'WARNING').count()
        recent_checks = ComplianceCheck.query.filter(
            ComplianceCheck.target_id.in_(user_target_ids)
            ).order_by(ComplianceCheck.scanned_at.desc()).limit(10).all()
    else:
        total_checks  = 0
        total_passed  = 0
        total_failed  = 0
        total_warning = 0
        recent_checks = []

    score = int((total_passed / total_checks) * 100) if total_checks > 0 else 0

    return render_template('dashboard.html',
        targets       = targets,
        total_checks  = total_checks,
        total_passed  = total_passed,
        total_failed  = total_failed,
        total_warning = total_warning,
        score         = score,
        recent_checks = recent_checks
    )
    
    
   
# ── ADMIN DASHBOARD ──
@main.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied. Admins only.')
        return redirect(url_for('main.dashboard'))

    # All users except admin
    users = User.query.filter(User.role != 'admin').all()

    # All targets with their owners
    targets = db.session.query(ScanTarget, User).join(
        User, ScanTarget.user_id == User.id
    ).all()

    # All checks with their owners
    total_checks  = ComplianceCheck.query.count()
    total_passed  = ComplianceCheck.query.filter_by(status='PASS').count()
    total_failed  = ComplianceCheck.query.filter_by(status='FAIL').count()
    total_warning = ComplianceCheck.query.filter_by(status='WARNING').count()
    score = int((total_passed / total_checks) * 100) if total_checks > 0 else 0

    # Recent activity with user info
    recent_activity = db.session.query(ComplianceCheck, ScanTarget, User)\
        .join(ScanTarget, ComplianceCheck.target_id == ScanTarget.id)\
        .join(User, ScanTarget.user_id == User.id)\
        .order_by(ComplianceCheck.scanned_at.desc())\
        .limit(20).all()

    return render_template('admin_dashboard.html',
        users           = users,
        targets         = targets,
        total_checks    = total_checks,
        total_passed    = total_passed,
        total_failed    = total_failed,
        total_warning   = total_warning,
        score           = score,
        recent_activity = recent_activity
    )


# ── ADMIN VIEW USER RESULTS ──
@main.route('/admin/results/<int:target_id>')
@login_required
def admin_view_results(target_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('main.dashboard'))

    target = ScanTarget.query.get_or_404(target_id)
    owner  = User.query.get(target.user_id)
    checks = ComplianceCheck.query.filter_by(target_id=target_id)\
                .order_by(ComplianceCheck.scanned_at.desc()).all()
    passed  = sum(1 for c in checks if c.status == 'PASS')
    failed  = sum(1 for c in checks if c.status == 'FAIL')
    warning = sum(1 for c in checks if c.status == 'WARNING')
    score   = int((passed / len(checks)) * 100) if checks else 0

    return render_template('admin_results.html',
        target  = target,
        owner   = owner,
        checks  = checks,
        passed  = passed,
        failed  = failed,
        warning = warning,
        score   = score
    )


# ── ADMIN DOWNLOAD REPORT ──
@main.route('/admin/report/<int:target_id>')
@login_required
def admin_download_report(target_id):
    from flask import send_file
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('main.dashboard'))

    target  = ScanTarget.query.get_or_404(target_id)
    owner   = User.query.get(target.user_id)
    checks  = ComplianceCheck.query.filter_by(target_id=target_id).all()
    results = []
    for c in checks:
        results.append({
            "requirement": c.requirement  if c.requirement  else "N/A",
            "description": c.description if c.description else "N/A",
            "status":      c.status      if c.status      else "N/A",
            "evidence":    c.evidence    if c.evidence    else "N/A",
            "risk_level":  c.risk_level  if c.risk_level  else "N/A"
        })

    if not results:
        flash('No scan results found for this target.')
        return redirect(url_for('main.admin_dashboard'))

    filename = f"admin_report_{owner.username}_{target.name}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", filename)
    generate_pdf_report(results, target.name, target.ip_address, filepath)
    return send_file(filepath, as_attachment=True)



# ── ADD TARGET ──
@main.route('/targets/add', methods=['GET', 'POST'])
@login_required
def add_target():
    if request.method == 'POST':
        name        = request.form.get('name').strip()
        ip_address  = request.form.get('ip_address').strip()
        system_type = request.form.get('system_type').strip()

        target = ScanTarget(
            user_id    = current_user.id,
            name       = name,
            ip_address = ip_address,
            system_type= system_type
        )
        db.session.add(target)
        db.session.commit()
        flash('Target added successfully.')
        return redirect(url_for('main.dashboard'))
    return render_template('add_target.html')


# ── RUN SCAN ──
@main.route('/scan/<int:target_id>')
@login_required
def run_scan(target_id):
    target = ScanTarget.query.filter_by(
        id      = target_id,
        user_id = current_user.id
    ).first_or_404()

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not ip_pattern.match(target.ip_address):
        flash('Invalid IP address format.')
        return redirect(url_for('main.dashboard'))

    scanner = PCIScanner(target.ip_address)
    results = scanner.run_all_checks()

    for r in results:
        check = ComplianceCheck(
            target_id   = target.id,
            requirement = r['requirement'],
            description = r['description'],
            status      = r['status'],
            evidence    = r['evidence'],
            risk_level  = r['risk_level']
        )
        db.session.add(check)

        if r['status'] == 'FAIL':
            db.session.flush()
            task = RemediationTask(
                user_id     = current_user.id,
                check_id    = check.id,
                description = f"Fix: {r['description']}",
                status      = 'Open'
            )
            db.session.add(task)

    db.session.commit()
    flash(f'Scan completed for {target.name}. {len(results)} checks performed.')
    return redirect(url_for('main.view_results', target_id=target.id))


# ── VIEW RESULTS ──
@main.route('/results/<int:target_id>')
@login_required
def view_results(target_id):
    target = ScanTarget.query.filter_by(
        id      = target_id,
        user_id = current_user.id
    ).first_or_404()

    checks  = ComplianceCheck.query.filter_by(target_id=target_id)\
                .order_by(ComplianceCheck.scanned_at.desc()).all()
    passed  = sum(1 for c in checks if c.status == 'PASS')
    failed  = sum(1 for c in checks if c.status == 'FAIL')
    warning = sum(1 for c in checks if c.status == 'WARNING')
    score   = int((passed / len(checks)) * 100) if checks else 0

    return render_template('results.html',
        target  = target,
        checks  = checks,
        passed  = passed,
        failed  = failed,
        warning = warning,
        score   = score
    )


# ── REMEDIATION ──
@main.route('/remediation')
@login_required
def remediation():
    # Only show THIS user's tasks
    tasks = RemediationTask.query.filter_by(
        user_id=current_user.id
    ).order_by(RemediationTask.created_at.desc()).all()
    return render_template('remediation.html', tasks=tasks)


# ── UPDATE TASK ──
@main.route('/remediation/update/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = RemediationTask.query.filter_by(
        id      = task_id,
        user_id = current_user.id
    ).first_or_404()
    task.status = request.form.get('status')
    db.session.commit()
    flash('Task updated successfully.')
    return redirect(url_for('main.remediation'))


# ── DOWNLOAD REPORT ──
@main.route('/report/<int:target_id>')
@login_required
def download_report(target_id):
    from flask import send_file
    target = ScanTarget.query.filter_by(
        id      = target_id,
        user_id = current_user.id
    ).first_or_404()

    checks  = ComplianceCheck.query.filter_by(target_id=target_id).all()
    results = []
    for c in checks:
        results.append({
            "requirement": c.requirement  if c.requirement  else "N/A",
            "description": c.description if c.description else "N/A",
            "status":      c.status      if c.status      else "N/A",
            "evidence":    c.evidence    if c.evidence    else "N/A",
            "risk_level":  c.risk_level  if c.risk_level  else "N/A"
        })

    if not results:
        flash('No scan results found. Please run a scan first.')
        return redirect(url_for('main.view_results', target_id=target_id))

    filename = f"report_{target.name}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", filename)
    generate_pdf_report(results, target.name, target.ip_address, filepath)
    return send_file(filepath, as_attachment=True)
