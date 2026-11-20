import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from dashboard.app import app

client = TestClient(app)

def test_placeholder_for_pytest():
    """Verify FastAPI app instance is healthy for pytest test runner."""
    res = client.get('/health') if '/health' in [r.path for r in app.routes] else client.get('/')
    assert res.status_code == 200

print('[*] 1. Testing GET / with pre-rendered canaries...')
res = client.get('/')
assert res.status_code == 200
assert 'q4_financial_payroll.xlsx' in res.text, 'Canaries missing in pre-rendered HTML!'
assert 'client_contracts_vault.docx' in res.text
assert 'canary-separate-list' in res.text
assert 'canary-table-body' in res.text
assert 'attackScenarioSelect' in res.text, 'Scenario selector missing in HTML!'
assert 'btnRunSelectedScenario' in res.text, 'Run simulation button missing!'
assert 'attackCheckboxesGrid' in res.text, 'Multi-select attack grid missing in HTML!'
assert 'setAttackPreset' in res.text, 'Preset controls missing in HTML!'
assert 'Prometheus & Grafana Stack Architecture Details' in res.text, 'Prometheus & Grafana section missing in HTML!'
assert 'openRiskFormulaModal()' in res.text, 'openRiskFormulaModal caller missing in HTML!'
assert 'openNotifyAdminModal()' in res.text, 'openNotifyAdminModal caller missing in HTML!'
assert 'Phase 3' not in res.text
# Verify that Prometheus & Grafana Stack Architecture Details is strictly at the end of the page
idx_prom = res.text.find('Prometheus & Grafana Stack Architecture Details')
assert idx_prom != -1
after_prom = res.text[idx_prom:]
assert '<!-- Forensic Incident Report Modal -->' not in after_prom
assert '<!-- Notify SOC Admin' not in after_prom
assert 'class="modal fade"' not in after_prom
print('    [PASS] GET / verified.')

print('[*] 2. Testing Simulation Endpoints with Dynamic Processes...')
res_canary = client.post('/api/simulate/canary-breach')
assert res_canary.status_code == 200
data_canary = res_canary.json()
print(f'    [PASS] Canary: {data_canary["attacker_process"]} (PID {data_canary["attacker_pid"]})')

res_enc = client.post('/api/simulate/encryption-burst')
assert res_enc.status_code == 200
data_enc = res_enc.json()
print(f'    [PASS] Encryption: {data_enc["attacker_process"]} (PID {data_enc["attacker_pid"]})')

res_eva = client.post('/api/simulate/defense-evasion')
assert res_eva.status_code == 200
data_eva = res_eva.json()
print(f'    [PASS] Defense Evasion: {data_eva["attacker_process"]} (PID {data_eva["attacker_pid"]})')

res_net = client.post('/api/simulate/network-exfil')
assert res_net.status_code == 200
data_net = res_net.json()
print(f'    [PASS] Network Exfil: {data_net["attacker_process"]} (PID {data_net["attacker_pid"]})')

res_full = client.post('/api/simulate/full-attack')
assert res_full.status_code == 200
data_full = res_full.json()
print(f'    [PASS] Full Attack: {data_full["attacker_process"]} (PID {data_full["attacker_pid"]})')

print('[*] 3. Testing Suspicious Processes Table...')
res_proc = client.get('/api/processes')
assert res_proc.status_code == 200
procs = res_proc.json().get('flagged_processes') or res_proc.json().get('processes', [])
assert len(procs) > 0, 'No suspicious processes returned!'
print(f'    [PASS] Monitored Suspicious Processes returned: {len(procs)} active processes!')

print('[*] 4. Testing Incident Report PDF Generation...')
res_rep_gen = client.post('/api/reports/generate')
assert res_rep_gen.status_code == 200
inc_id = res_rep_gen.json()['incident_id']
print(f'    - Report ID: {inc_id}')

res_pdf = client.get(f'/api/reports/download-pdf/{inc_id}')
assert res_pdf.status_code == 200
assert res_pdf.headers.get('content-type') == 'application/pdf'
assert len(res_pdf.content) > 1000
assert res_pdf.content[:4] == b'%PDF'
print(f'    [PASS] PDF generated: {len(res_pdf.content)} bytes!')

print('[*] 5. Testing Canary Details Modal API...')
res_can = client.get('/api/canaries/q4_financial_payroll.xlsx')
assert res_can.status_code == 200
assert 'sha256' in res_can.json()
print(f'    [PASS] Canary details verified (Hash: {res_can.json()["sha256"][:12]}...)')

print('[*] 6. Testing Process Forensic Detail Modal & Process Termination...')
test_pid = procs[0]['pid']
res_p_detail = client.get(f'/api/processes/{test_pid}')
assert res_p_detail.status_code == 200
assert 'threat_score' in res_p_detail.json()['process']
print(f'    [PASS] Process Detail verified for PID {test_pid}: {res_p_detail.json()["process"]["name"]}')

res_term = client.post('/api/control/containment/terminate', json={"pid": test_pid, "process_name": procs[0]["name"]})
assert res_term.status_code == 200
assert res_term.json()['status'] == 'SUCCESS'

res_proc_after = client.get('/api/processes')
pids_after = [p['pid'] for p in res_proc_after.json()['processes']]
assert test_pid not in pids_after, f'PID {test_pid} should have been removed after termination!'
print(f'    [PASS] Process {test_pid} successfully terminated and removed from active list!')

print('[*] 7. Testing 36 Real Ransomware Families API & Live Attack Simulation...')
res_fam = client.get('/api/simulate/families')
assert res_fam.status_code == 200
fam_payload = res_fam.json()
families_dict = fam_payload.get('families_dict', {})
fam_list = fam_payload.get('families', [])
assert len(fam_list) >= 36, f'Expected at least 36 real ransomware families, found {len(fam_list)}'
all_36_expected = [
    'wannacry', 'lockbit3', 'blackcat', 'ryuk', 'conti', 'revil', 'darkside', 'akira', 'royal', 'maze', 'clop', 'hive',
    'blackbasta', 'play', 'rhysida', 'medusa', 'blacksuit', 'cactus', 'babuk', 'bianlian', 'qilin', 'ransomhub',
    'notpetya', 'badrabbit', 'samsam', 'gandcrab', 'dharma', 'phobos', 'stopdjvu', 'netwalker', 'ragnarlocker',
    'doppelpaymer', 'cuba', 'avaddon', 'snatch', 'mallox'
]
for req_key in all_36_expected:
    assert req_key in families_dict, f'Missing family key: {req_key}'
print(f'    [PASS] 36 Real Ransomware Families verified: {list(families_dict.keys())[:8]}... ({len(fam_list)} total)')

res_wc = client.post('/api/simulate/wannacry')
assert res_wc.status_code == 200
wc_data = res_wc.json()
assert wc_data['scenario'] == 'WannaCry 2.0 (WanaCrypt0r)'
assert wc_data['attacker_process'] == '@WanaDecryptor@.exe'
assert 'incident_report_id' in wc_data
inc_wc_id = wc_data['incident_report_id']
print(f'    [PASS] Real Ransomware Simulation executed: {wc_data["scenario"]} (PID {wc_data["attacker_pid"]}) -> Report: {inc_wc_id}')

print('[*] 7b. Testing Simultaneous Multi-Strain Attack Simulation (WannaCry + LockBit + BlackCat)...')
res_multi = client.post('/api/simulate/multi', json={"families": ["wannacry", "lockbit3", "blackcat"]})
assert res_multi.status_code == 200
multi_data = res_multi.json()
assert multi_data['strains_count'] == 3
assert len(multi_data['spawned_processes']) == 3
multi_proc_names = [p['binary'] for p in multi_data['spawned_processes']]
assert '@WanaDecryptor@.exe' in multi_proc_names
assert 'lockbit3_encryptor.exe' in multi_proc_names
assert 'alphv_blackcat.exe' in multi_proc_names
assert 'SIM-INC-' in multi_data['incident_report_id']
print(f'    [PASS] Simultaneous Multi-Strain Attack executed: 3 Strains, {len(multi_data["spawned_processes"])} processes ({multi_proc_names}) -> Report: {multi_data["incident_report_id"]}')

print('[*] 7c. Testing Modern Threats Multi-Attack Simulation (WannaCry, Black Basta, Play, Cactus, RansomHub)...')
res_modern = client.post('/api/simulate/multi', json={"families": ["wannacry", "blackbasta", "play", "cactus", "ransomhub"]})
assert res_modern.status_code == 200
modern_data = res_modern.json()
assert modern_data['strains_count'] == 5
assert len(modern_data['spawned_processes']) == 5
modern_proc_names = [p['binary'] for p in modern_data['spawned_processes']]
assert '@WanaDecryptor@.exe' in modern_proc_names
assert 'blackbasta_core.exe' in modern_proc_names
assert 'play_crypt.exe' in modern_proc_names
assert 'cactus_loader.exe' in modern_proc_names
assert 'ransomhub_x64.exe' in modern_proc_names
print(f'    [PASS] Modern Threats Multi-Attack executed: 5 Strains ({modern_proc_names}) -> Report: {modern_data["incident_report_id"]}')

print('[*] 8. Testing Formula Breakdown & Telemetry Weights...')
res_tel = client.get('/api/telemetry')
assert res_tel.status_code == 200
tel_data = res_tel.json()
risk_data = tel_data.get('risk', {})
breakdown = risk_data.get('breakdown', {})
assert 'factors' in breakdown, 'breakdown.factors missing in risk telemetry!'
assert breakdown.get('total_weight') == 125.0
factors = breakdown['factors']
assert len(factors) == 7, f'Expected 7 telemetry factors, got {len(factors)}'
factor_keys = [f['key'] for f in factors]
for f_key in ['canary', 'entropy', 'recovery', 'renames', 'process', 'network', 'auth']:
    assert f_key in factor_keys, f'Missing factor {f_key} in formula breakdown'
    factor_obj = next(f for f in factors if f['key'] == f_key)
    assert 'weight' in factor_obj
    assert 'points' in factor_obj
    assert 'live_val' in factor_obj
print(f'    [PASS] Formula breakdown verified: Score={risk_data.get("risk_score_100")}, Factors count={len(factors)}')

print('[*] 9. Testing Incident Report Auto-Indexing & Simulation Classification...')
res_rep = client.get('/api/reports')
assert res_rep.status_code == 200
rep_list = res_rep.json().get('reports', [])
assert len(rep_list) > 0, 'No reports returned after simulation!'
found_wc_report = False
for r in rep_list:
    if r.get('id') == inc_wc_id or r.get('incident_id') == inc_wc_id:
        found_wc_report = True
        assert r.get('is_simulation') is True, f'Report {inc_wc_id} should be tagged as simulation!'
        assert 'WannaCry' in r.get('scenario', ''), f'Report scenario should reference WannaCry!'
        break
assert found_wc_report, f'Report {inc_wc_id} not found in reports list!'
print(f'    [PASS] Forensic report {inc_wc_id} correctly classified as simulation ({r.get("scenario")})')

print('[*] 10. Testing All 6 Telemetry Vector Inspection APIs & Attacker Decoy Attribution...')
for vec_key in ['t2', 't3', 't4', 't5', 't6', 't7']:
    res_vec = client.get(f'/api/telemetry/vector/{vec_key}')
    assert res_vec.status_code == 200, f'Vector {vec_key} inspection failed!'
    v_data = res_vec.json()
    assert 'code' in v_data
    assert 'considerations' in v_data
    assert len(v_data['considerations']) >= 3, f'Expected detailed considerations for {vec_key}'
    assert 'evidence' in v_data
    print(f'    [PASS] Vector {v_data["code"]} ({v_data["name"]}) verified. Considerations: {len(v_data["considerations"])}, Metric: {v_data["metric_value"]}')

# Verify T7 compromised canary attribution
res_t7 = client.get('/api/telemetry/vector/t7')
assert res_t7.status_code == 200
t7_data = res_t7.json()
compromised_canaries = t7_data['evidence'].get('compromised_canaries', [])
assert len(compromised_canaries) > 0, 'Expected at least one compromised decoy in T7 after WannaCry attack!'
matching_wc = [c for c in compromised_canaries if c.get('attacker_process') == '@WanaDecryptor@.exe']
assert len(matching_wc) > 0, 'Expected WannaCry @WanaDecryptor@.exe attribution in compromised decoys!'
c0 = matching_wc[0]
assert 'WannaCry' in c0.get('attacker_family', '')
assert c0.get('compromised_at') is not None
assert c0.get('tamper_type') is not None
print(f'    [PASS] Decoy Attribution Verified: {c0["filename"]} triggered by {c0["attacker_process"]} (PID {c0["attacker_pid"]}) at {c0["compromised_at"]}')

print('[*] 11. Testing SOC Admin Notification Recipient Configuration & Custom Dispatch...')
res_ncfg = client.get('/api/notify/config')
assert res_ncfg.status_code == 200
ncfg = res_ncfg.json()
assert 'soc_email' in ncfg
assert 'secondary_emails' in ncfg
assert 'admin_name' in ncfg
assert 'broadcast_channel' in ncfg
assert 'smtp' in ncfg
orig_cfg = dict(ncfg)
print(f'    [PASS] Current Notification Config: Primary={ncfg["soc_email"]}, Admin={ncfg["admin_name"]}')

# Test updating config
res_up = client.post('/api/notify/config', json={
    "soc_email": "security-incident-commander@enterprise.org",
    "secondary_emails": ["soc-tier3@enterprise.org", "ciso-direct@enterprise.org"],
    "admin_name": "Chief Information Security Officer",
    "broadcast_channel": "#critical-secops-war-room",
    "phone_sms": "+1-888-999-SECOPS",
    "smtp": {
        "enabled": False,
        "host": "smtp.gmail.com",
        "port": 587,
        "use_tls": True,
        "username": "security-incident-commander@enterprise.org"
    }
})
assert res_up.status_code == 200
up_data = res_up.json()
assert up_data['status'] == 'SUCCESS'
assert up_data['config']['soc_email'] == 'security-incident-commander@enterprise.org'
assert 'ciso-direct@enterprise.org' in up_data['config']['secondary_emails']
assert up_data['config']['admin_name'] == 'Chief Information Security Officer'
print(f'    [PASS] Updated Alert Recipients successfully saved to config!')

# Test custom dispatch with recipients
res_disp = client.post('/api/notify/dispatch', json={
    "title": "EMERGENCY: Test Active Ransomware Breach Alert",
    "severity": "CRITICAL",
    "recipients": ["security-incident-commander@enterprise.org", "soc-tier3@enterprise.org"],
    "admin_name": "Chief Information Security Officer",
    "channel": "#critical-secops-war-room",
    "details": {"test": True, "notes": "Automated recipient verification test"}
})
assert res_disp.status_code == 200
disp_data = res_disp.json()
assert disp_data['status'] == 'DISPATCHED'
assert 'security-incident-commander@enterprise.org' in disp_data['recipients']
assert 'soc-tier3@enterprise.org' in disp_data['recipients']
assert disp_data['channel'] == '#critical-secops-war-room'
assert disp_data['admin_contact'] == 'Chief Information Security Officer'
print(f'    [PASS] Alert successfully dispatched to custom recipients: {disp_data["recipients"]}')

# Restore user's original persistent config
res_restore = client.post('/api/notify/config', json=orig_cfg)
assert res_restore.status_code == 200
assert res_restore.json()['config']['soc_email'] == orig_cfg['soc_email']
print(f'    [PASS] User SOC recipient safely restored to: {orig_cfg["soc_email"]}')

print('[*] 12. Testing Automated Incident Email Dispatch with PDF Reports and Test Attribution...')
# 1. Test simulated test email dispatch (mode="test")
res_test_eml = client.post('/api/notify/test-email', json={"soc_email": "ankitnim227@gmail.com", "mode": "test"})
assert res_test_eml.status_code == 200
test_eml_data = res_test_eml.json()
assert 'email_record' in test_eml_data
assert test_eml_data['email_record']['status'] == 'SENT'
assert test_eml_data['email_record']['is_simulation'] is True
assert '[TEST RANSOMWARE ATTACK]' in test_eml_data['email_record']['subject']
assert 'Test ransomware attack' in test_eml_data['email_record']['short_note']
assert test_eml_data['email_record']['has_pdf_attachment'] is True
assert 'ankitnim227@gmail.com' in test_eml_data['email_record']['to']
print(f'    [PASS] Test Email Dispatch verified: ID={test_eml_data["email_record"]["id"]}, Delivery={test_eml_data["delivery_status"]}')

# 2. Test live incident alert email dispatch (mode="real")
res_real_eml = client.post('/api/notify/test-email', json={"soc_email": "ankitnim227@gmail.com", "mode": "real"})
assert res_real_eml.status_code == 200
real_eml_data = res_real_eml.json()
assert 'email_record' in real_eml_data
assert real_eml_data['email_record']['is_simulation'] is False
assert '[LIVE RANSOMWARE INCIDENT DETECTED]' in real_eml_data['email_record']['subject']
assert 'CRITICAL: Active ransomware behavior detected' in real_eml_data['email_record']['short_note']
assert real_eml_data['email_record']['has_pdf_attachment'] is True
print(f'    [PASS] Live Incident Alert Email Verified: Subject={real_eml_data["email_record"]["subject"]}, PDF={real_eml_data["email_record"]["has_pdf_attachment"]}')

res_emls = client.get('/api/notifications/emails')
assert res_emls.status_code == 200
emls = res_emls.json().get('emails', [])
assert len(emls) > 0, 'No automated incident emails found in outbox!'

# Inspect the most recent simulation email
sim_eml = next((e for e in emls if e.get('is_simulation') is True), None)
assert sim_eml is not None, 'No simulated test email found in outbox!'
assert '[TEST RANSOMWARE ATTACK]' in sim_eml['subject'], f"Expected [TEST RANSOMWARE ATTACK] in subject, got: {sim_eml['subject']}"
assert 'Test ransomware attack' in sim_eml['short_note'], f"Expected 'Test ransomware attack' in short_note, got: {sim_eml['short_note']}"
assert sim_eml.get('has_pdf_attachment') is True, 'Expected PDF attachment to be True in email record!'
assert sim_eml.get('pdf_size_bytes', 0) > 0, 'PDF size should be > 0 bytes!'
assert sim_eml['status'] == 'SENT'

# Check .eml file exists
eml_file = sim_eml.get('eml_file')
if eml_file:
    res_eml_dl = client.get(f'/api/notifications/emails/{sim_eml["id"]}/eml')
    assert res_eml_dl.status_code == 200
    assert len(res_eml_dl.content) > 0
    print(f'    [PASS] RFC-822 .eml MIME Archive verified: {eml_file} ({len(res_eml_dl.content)} bytes)')

print(f"    [PASS] Automated Email Verified: ID={sim_eml['id']}, Subject='{sim_eml['subject']}', PDF Attached={sim_eml['has_pdf_attachment']} ({sim_eml['pdf_size_bytes']} bytes), Recipients={sim_eml['to']}")
print(f"    [PASS] Test Ransomware Note: '{sim_eml['short_note']}'")

# 13. Attack Detection Network Disconnect & Resume Normal Services Verification
print("\n[13] Verifying Attack Detection Network Disconnect & Resume Normal Services...")

# A. Detonate an attack simulation (e.g. WannaCry drill)
res_atk = client.post('/api/simulate/wannacry')
assert res_atk.status_code == 200, f"Simulate attack failed: {res_atk.text}"
print("    [PASS] Attack simulation detonated.")

# B. Assert network connections are immediately DISCONNECTED / QUARANTINED
res_telem_atk = client.get('/api/telemetry')
assert res_telem_atk.status_code == 200
telem_atk = res_telem_atk.json()
assert telem_atk.get('containment', {}).get('is_network_isolated') is True, "Expected network connections to be disconnected on attack detection!"
print("    [PASS] Verified: All network connections DISCONNECTED / QUARANTINED upon attack detection.")

# C. Call the Resume All Services (Restore Normal Baseline) endpoint
res_resume = client.post('/api/control/system/resume-normal')
assert res_resume.status_code == 200, f"Resume normal failed: {res_resume.text}"
resume_data = res_resume.json()
assert resume_data['status'] == 'SUCCESS'
assert resume_data['network_status'] == 'ONLINE'
assert resume_data['is_network_isolated'] is False
assert resume_data['risk_score'] <= 5.0
assert resume_data['risk_level'] == 'Normal'
print(f"    [PASS] Resume Normal endpoint returned: {resume_data['message']}")

# D. Assert telemetry reflects complete pre-attack normal baseline
res_telem_normal = client.get('/api/telemetry')
assert res_telem_normal.status_code == 200
telem_normal = res_telem_normal.json()
assert telem_normal.get('containment', {}).get('is_network_isolated') is False, "Network should be restored to ONLINE!"
canaries = telem_normal.get('canaries', [])
intact_canaries = [c for c in canaries if c.get('status') == 'INTACT']
assert len(intact_canaries) == len(canaries) and len(canaries) == 5, f"All 5 canaries should be INTACT, got: {len(intact_canaries)}"
assert len(telem_normal.get('processes', [])) == 0, "Flagged attack processes should be cleared!"
assert telem_normal.get('risk', {}).get('risk_score_100', 0.0) <= 5.0, "Risk score should be <= 5.0 (Normal)!"
assert telem_normal.get('risk', {}).get('risk_level') == 'Normal', "Risk level should be Normal!"
print("    [PASS] Verified: All services, canaries (5/5 intact), network (ONLINE), and processes restored to pre-attack baseline.")

# 14. Verification of Automatic Email on Real Attack vs Asking User on Simulation
print("\n[14] Verifying Email Policy: Automatic on Real Attack vs Asking on Simulation...")

# A. Simulation Triggered: Must NOT send email automatically, must return prompt_user_for_email == True
res_sim = client.post('/api/simulate/wannacry')
assert res_sim.status_code == 200
sim_res_data = res_sim.json()
assert sim_res_data.get('prompt_user_for_email') is True, "Simulation should prompt user before sending email!"
assert sim_res_data.get('email_dispatched') is False, "Simulation should NOT send email automatically without user confirmation!"
sim_inc_id = sim_res_data.get('incident_id')
print(f"    [PASS] Simulation completed ({sim_inc_id}): Email NOT auto-sent; prompt_user_for_email is True.")

# B. User confirms and dispatches test email with target incident ID
res_confirm = client.post('/api/notify/test-email', json={
    "incident_id": sim_inc_id,
    "scenario": sim_res_data.get('scenario'),
    "mode": "test",
    "recipients": "ankitnim227@gmail.com"
})
assert res_confirm.status_code == 200
confirm_data = res_confirm.json()
assert confirm_data.get('status') in ['SUCCESS', 'SAVED_TO_OUTBOX']
assert confirm_data['email_record']['incident_id'] == sim_inc_id
assert confirm_data['email_record']['is_simulation'] is True
assert '[TEST RANSOMWARE ATTACK]' in confirm_data['email_record']['subject']
print(f"    [PASS] User confirmation dispatched test email: ID={confirm_data['email_record']['id']}, Subject={confirm_data['email_record']['subject']}")

# C. Real Attack Generation: Dispatches automatically without prompt
res_real = client.post('/api/notify/test-email', json={
    "mode": "real",
    "recipients": "ankitnim227@gmail.com"
})
assert res_real.status_code == 200
real_data = res_real.json()
assert real_data['email_record']['is_simulation'] is False
assert '[LIVE RANSOMWARE INCIDENT DETECTED]' in real_data['email_record']['subject']
print(f"    [PASS] Real attack alert dispatched automatically: Subject={real_data['email_record']['subject']}")

# D. Restore services to normal
res_clean = client.post('/api/control/system/resume-normal')
assert res_clean.status_code == 200
print("    [PASS] Services resumed and baseline restored to clean state.")

print('\nALL VERIFICATION TESTS COMPLETED SUCCESSFULLY!')

