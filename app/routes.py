from flask  import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from app.models import User, ScanTarget, ComplianceCheck, RemediationTask
from app.scanner import PCIScanner
from app.report import generate_pdf_report
from datetime import datetime, timezone
import os
main = Blueprint('main', __name__)



#---- USER LOADER ----#
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#---LOGIN---#
@main.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('invalid username or password')
    return render_template('login.html')


#--LOGOUT---#
@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


#----DASHBOARD---#
@main.route('/dashboard')
@login_required
def dashboard():
    targets = ScanTarget.query.all()
    total_checks = ComplianceCheck.query.count()
    total_passed = ComplianceCheck.query.filter_by(status='PASS').count()
    total_failed = ComplianceCheck.query.filter_by(status='FAIL').count()
    total_warning = ComplianceCheck.query.filter_by(status='WARNING').count()
    score = int((total_passed / total_checks) *100) if total_checks > 0 else 0
    recent_checks = ComplianceCheck.query.order_by(ComplianceCheck.scanned_at.desc()).limit(10).all()
    
    return render_template('dashboard.html', targets=targets, total_check=total_checks, total_passed=total_passed, total_failed=total_failed, total_warning=total_warning, score=score, recent_checks=recent_checks)



#-- ADD TARGET---#
@main.route('/targets/add', methods=['GET','POST'])
@login_required
def add_target():
    if request.method=='POST':
        name = request.form.get('name')
        ip_address = request.form.get('ip_address')
        system_type = request.form.get('system_type')
        target = ScanTarget(name=name, ip_address=ip_address, system_type=system_type)
        db.session.add(target)
        db.session.commit()
        flash('Target added successfully')
        return redirect(url_for('main.dashboard'))
    return render_template('add_target.html')



#---_RUN SCAN ___#
@main.route('/scan/<int:target_id>')
@login_required
def run_scan(target_id):
    import re
    target = ScanTarget.query.get_or_404(target_id)
    
    #validate IP address format
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if not ip_pattern.match(target.ip_address):
        flash("invalid IP address format. Please use format: 192.168.1.1")
        return redirect(url_for('main.dashboard'))
    scanner = PCIScanner(target.ip_address)
    results = scanner.run_all_checks()
    
    for r in results:
        check = ComplianceCheck(
            target_id = target_id,
            requirement = r['requirement'],
            description = r['description'],
            status = r['status'],
            evidence = r['evidence'],
            risk_level = r['risk_level']
            
        )
        db.session.add(check)
        
        #auto create remediation task for failures
        if r['status']== 'FAIL':
            db.session.flush()
            task = RemediationTask(
                check_id = check.id,
                description = f"Fix: {r['description']}",
                status = "Open"
            )
            db.session.add(task)
            
    db.session.commit()
    flash(f'Scan completed for {target.name}, {len(results)} checks performed.')
    return redirect(url_for('main.view_results', target_id=target.id))



#____VIEW RESULTS___
@main.route('/results/<int:target_id>')
@login_required
def view_results(target_id):
    target = ScanTarget.query.get_or_404(target_id)
    checks = ComplianceCheck.query.filter_by(target_id=target_id)\
        .order_by(ComplianceCheck.scanned_at.desc()).all()
    passed = sum(1 for c in checks if c.status == 'PASS')
    failed = sum(1 for c in checks if c.status == 'FAIL')
    warning = sum(1 for c in checks if c.status == 'WARNING')
    score = int ((passed/len(checks))* 100) if checks else 0
    return render_template('results.html', 
                           target=target, checks=checks,
                           passed=passed, failed=failed,
                           warning=warning, score=score)   
    
    
    
    
# --- REMEDIATION ---#
@main.route('/remediation')
@login_required
def remediation():
    tasks = RemediationTask.query.order_by(RemediationTask.created_at.desc()).all()
    return render_template('remediation.html', tasks=tasks)



#--UPDATE TASK STATUS --
@main.route('/remediation/update/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = RemediationTask.query.get_or_404(task_id)
    task.status = request.form.get('status')
    db.session.commit()
    flash('Task updated successfully')
    return redirect(url_for('main.remediation'))


#---GENERATE PDF REPORT
@main.route('/report/<int:target_id>')
@login_required
def download_report(target_id):
    from flask import send_file
    target = ScanTarget.query.get_or_404(target_id)
    checks = ComplianceCheck.query.filter_by(target_id=target_id).all()
    results = [{
        "requirement": c.requirement,
        "description": c.description,
        "status": c.status,
        "evidence": c.evidence,
        "risk_level": c.risk_level
    }for c in checks]
    
    filename = f"report_{target.name}_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", filename)
    generate_pdf_report(results, target.name, target.ip_address, filepath)
    return send_file(filepath, as_attachment=True)    
        
        
        
        
        
        
        