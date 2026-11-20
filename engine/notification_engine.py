"""
Admin Notification & SOC Alerting Engine
Dispatches real-time alerts to system administrators and SOC teams
via Webhook, Email simulations, and centralized event streams.
Allows dynamic editing and configuration of alert recipients and channels.
Automatically delivers email alerts with PDF forensic reports whenever incidents are detected.
Features full MIME multipart generation, RFC-822 .eml archiving, and live SMTP transmission.
"""

import time
import json
import os
import threading
import urllib.request
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import formatdate, make_msgid
from typing import Dict, List, Any, Optional

class NotificationEngine:
    def __init__(self, config: Dict[str, Any], config_path: Optional[str] = None):
        self.config_path = config_path
        self.raw_config = config
        self.config = config.get("admin_notifications", {})
        self.soc_email = self.config.get("soc_email", "ankitnim227@gmail.com")
        self.secondary_emails: List[str] = self.config.get("secondary_emails", ["soc-tier3@enterprise.org", "ciso-direct@enterprise.org"])
        self.admin_name = self.config.get("admin_name", "Chief Information Security Officer")
        self.webhook_url = self.config.get("webhook_url", "http://127.0.0.1:8000/api/webhook/alerts")
        self.channel = self.config.get("broadcast_channel", "#critical-secops-war-room")
        self.phone_sms = self.config.get("phone_sms", "+1-888-999-SECOPS")
        self.cooldown_sec = self.config.get("alert_cooldown_sec", 5)
        self.prompt_before_simulation_email = bool(self.config.get("prompt_before_simulation_email", True))
        self.auto_send_real_attack_email = bool(self.config.get("auto_send_real_attack_email", True))

        # SMTP Configuration
        smtp_cfg = self.config.get("smtp", {})
        self.smtp_config = {
            "enabled": bool(smtp_cfg.get("enabled", False)),
            "host": str(smtp_cfg.get("host", "smtp.gmail.com")),
            "port": int(smtp_cfg.get("port", 587)),
            "use_tls": bool(smtp_cfg.get("use_tls", True)),
            "username": str(smtp_cfg.get("username", self.soc_email)),
            "password": str(smtp_cfg.get("password", "")),
            "from_email": str(smtp_cfg.get("from_email", self.soc_email)),
            "from_name": str(smtp_cfg.get("from_name", "RansomGuard EDR SOC Alerting"))
        }

        self.last_alert_time = 0.0
        self.sent_notifications: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def get_config(self) -> Dict[str, Any]:
        """Returns the current alerting, recipient, and SMTP configuration."""
        with self._lock:
            smtp_copy = dict(self.smtp_config)
            # Mask password if populated for UI safety
            if smtp_copy.get("password"):
                smtp_copy["has_password"] = True
            else:
                smtp_copy["has_password"] = False
            return {
                "soc_email": self.soc_email,
                "secondary_emails": list(self.secondary_emails),
                "admin_name": self.admin_name,
                "webhook_url": self.webhook_url,
                "broadcast_channel": self.channel,
                "phone_sms": self.phone_sms,
                "alert_cooldown_sec": self.cooldown_sec,
                "prompt_before_simulation_email": self.prompt_before_simulation_email,
                "auto_send_real_attack_email": self.auto_send_real_attack_email,
                "smtp": smtp_copy
            }

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Updates and persists the alert recipient and SMTP settings."""
        with self._lock:
            if "soc_email" in new_config and new_config["soc_email"]:
                self.soc_email = str(new_config["soc_email"]).strip()
            if "secondary_emails" in new_config:
                sec = new_config["secondary_emails"]
                if isinstance(sec, str):
                    self.secondary_emails = [e.strip() for e in sec.split(",") if e.strip()]
                elif isinstance(sec, list):
                    self.secondary_emails = [str(e).strip() for e in sec if str(e).strip()]
            if "admin_name" in new_config and new_config["admin_name"]:
                self.admin_name = str(new_config["admin_name"]).strip()
            if "webhook_url" in new_config and new_config["webhook_url"]:
                self.webhook_url = str(new_config["webhook_url"]).strip()
            if "broadcast_channel" in new_config and new_config["broadcast_channel"]:
                self.channel = str(new_config["broadcast_channel"]).strip()
            if "phone_sms" in new_config and new_config["phone_sms"]:
                self.phone_sms = str(new_config["phone_sms"]).strip()
            if "alert_cooldown_sec" in new_config:
                try:
                    self.cooldown_sec = max(1, int(new_config["alert_cooldown_sec"]))
                except Exception:
                    pass
            if "prompt_before_simulation_email" in new_config:
                self.prompt_before_simulation_email = bool(new_config["prompt_before_simulation_email"])
            if "auto_send_real_attack_email" in new_config:
                self.auto_send_real_attack_email = bool(new_config["auto_send_real_attack_email"])

            # Update SMTP settings
            if "smtp" in new_config and isinstance(new_config["smtp"], dict):
                smtp_in = new_config["smtp"]
                if "enabled" in smtp_in:
                    self.smtp_config["enabled"] = bool(smtp_in["enabled"])
                if "host" in smtp_in and smtp_in["host"]:
                    self.smtp_config["host"] = str(smtp_in["host"]).strip()
                if "port" in smtp_in:
                    try:
                        self.smtp_config["port"] = int(smtp_in["port"])
                    except Exception:
                        pass
                if "use_tls" in smtp_in:
                    self.smtp_config["use_tls"] = bool(smtp_in["use_tls"])
                if "username" in smtp_in and smtp_in["username"]:
                    self.smtp_config["username"] = str(smtp_in["username"]).strip()
                if "password" in smtp_in:
                    pwd = str(smtp_in["password"]).strip()
                    # Only overwrite if non-empty or explicitly changing
                    if pwd:
                        self.smtp_config["password"] = pwd
                if "from_email" in smtp_in and smtp_in["from_email"]:
                    self.smtp_config["from_email"] = str(smtp_in["from_email"]).strip()
                if "from_name" in smtp_in and smtp_in["from_name"]:
                    self.smtp_config["from_name"] = str(smtp_in["from_name"]).strip()

        # Persist to disk if config_path given
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    full_cfg = json.load(f)
                
                # Save without masking password on disk
                with self._lock:
                    cfg_to_save = {
                        "soc_email": self.soc_email,
                        "secondary_emails": list(self.secondary_emails),
                        "admin_name": self.admin_name,
                        "webhook_url": self.webhook_url,
                        "broadcast_channel": self.channel,
                        "phone_sms": self.phone_sms,
                        "alert_cooldown_sec": self.cooldown_sec,
                        "prompt_before_simulation_email": self.prompt_before_simulation_email,
                        "auto_send_real_attack_email": self.auto_send_real_attack_email,
                        "smtp": dict(self.smtp_config)
                    }
                full_cfg["admin_notifications"] = cfg_to_save
                with open(self.config_path, "w") as f:
                    json.dump(full_cfg, f, indent=2)
            except Exception as e:
                print(f"[!] Warning saving updated notification config to disk: {e}")

        return self.get_config()

    def _build_mime_email(
        self,
        recipients: List[str],
        subject: str,
        inc_id: str,
        indicator_label: str,
        note: str,
        score: float,
        risk_level: str,
        scenario: str,
        is_sim: bool,
        pdf_path: Optional[str] = None,
        pdf_filename: Optional[str] = None
    ) -> MIMEMultipart:
        """
        Builds a full RFC-822/2822 compliant MIME email with HTML body, plain text alternative,
        headers, and attached PDF incident report.
        """
        msg = MIMEMultipart("mixed")
        from_name = self.smtp_config.get("from_name", "RansomGuard EDR SOC Alerting")
        from_email = self.smtp_config.get("from_email", self.soc_email)

        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = ", ".join(recipients)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="ransomguard.security")
        msg["X-Priority"] = "1 (Highest)"
        msg["X-RansomGuard-Incident-ID"] = inc_id
        msg["X-RansomGuard-Simulation"] = "TRUE" if is_sim else "FALSE"

        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Plain text body
        plain_text = f"""================================================================================
RANSOMGUARD BEHAVIORAL EDR - INCIDENT FORENSIC NOTIFICATION
================================================================================
Classification: {indicator_label}
Incident ID:    {inc_id}
Adversary/Scenario: {scenario}
Risk Level:     {risk_level} (Composite Score: {score:.1f}/100)
Timestamp:      {timestamp_str}
Recipients:     {', '.join(recipients)}

--------------------------------------------------------------------------------
INCIDENT SUMMARY & NOTE:
--------------------------------------------------------------------------------
{note}

--------------------------------------------------------------------------------
FORENSIC ATTACHMENT:
--------------------------------------------------------------------------------
Attached Dossier: {pdf_filename or f'{inc_id}.pdf'}
Full NIST SP 800-61 Rev 2 / MITRE ATT&CK forensic incident report attached.
================================================================================
"""

        # HTML styled email body
        badge_bg = "#7c3aed" if is_sim else "#dc2626"
        note_box_border = "#8b5cf6" if is_sim else "#ef4444"
        note_box_bg = "rgba(124, 58, 237, 0.12)" if is_sim else "rgba(220, 38, 38, 0.12)"

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #f8fafc; margin: 0; padding: 20px; }}
  .container {{ max-width: 680px; margin: 0 auto; background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; overflow: hidden; }}
  .header {{ background: #0a0f1d; padding: 20px 24px; border-bottom: 3px solid {badge_bg}; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; background: {badge_bg}; color: #ffffff; margin-bottom: 8px; text-transform: uppercase; }}
  .header h2 {{ margin: 0; font-size: 18px; color: #f8fafc; font-weight: 700; }}
  .content {{ padding: 24px; }}
  .note-box {{ background: {note_box_bg}; border-left: 4px solid {note_box_border}; padding: 14px 16px; border-radius: 4px; margin-bottom: 20px; color: #e2e8f0; font-size: 13.5px; line-height: 1.5; }}
  .table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 13px; }}
  .table th {{ background: #0f172a; color: #94a3b8; text-align: left; padding: 8px 12px; border: 1px solid #1e293b; width: 35%; }}
  .table td {{ background: #131b2e; color: #f1f5f9; padding: 8px 12px; border: 1px solid #1e293b; }}
  .attachment-card {{ background: #0a0f1d; border: 1px solid #334155; border-radius: 6px; padding: 14px 16px; margin-bottom: 16px; }}
  .footer {{ background: #0a0f1d; padding: 14px 24px; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <span class="badge">{indicator_label}</span>
    <h2>{subject}</h2>
  </div>
  <div class="content">
    <div class="note-box">
      <strong style="color: #38bdf8; display: block; margin-bottom: 4px;">📢 SOC Incident Alert Note:</strong>
      {note}
    </div>
    
    <table class="table">
      <tr><th>Incident Reference</th><td><strong style="color: #38bdf8;">{inc_id}</strong></td></tr>
      <tr><th>Adversary Profile / Scenario</th><td><code>{scenario}</code></td></tr>
      <tr><th>Composite Threat Rating</th><td><strong style="color: {'#a855f7' if is_sim else '#ef4444'};">{score:.1f} / 100.0 &mdash; {risk_level}</strong></td></tr>
      <tr><th>Automated Containment</th><td>Immediate Process Termination (SIGKILL) &amp; Endpoint Network Quarantine</td></tr>
      <tr><th>Audit UTC Timestamp</th><td>{timestamp_str}</td></tr>
      <tr><th>Designated Recipients</th><td>{', '.join(recipients)}</td></tr>
    </table>

    <div class="attachment-card">
      <strong style="color: #f59e0b; font-size: 13px;">📎 Forensic Incident Report Attached:</strong><br>
      <span style="color: #94a3b8; font-size: 12px;">{pdf_filename or f'{inc_id}.pdf'} (NIST SP 800-61 / MITRE ATT&CK Technical Dossier)</span>
    </div>
  </div>
  <div class="footer">
    RansomGuard Multi-Vector Behavioral Early Warning Framework &bull; Autonomous SOC Response Engine
  </div>
</div>
</body>
</html>"""

        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(plain_text, "plain", "utf-8"))
        alt.attach(MIMEText(html_body, "html", "utf-8"))
        msg.attach(alt)

        # Attach PDF report if present
        if pdf_path and os.path.exists(pdf_path):
            try:
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
                pdf_part = MIMEApplication(pdf_bytes, _subtype="pdf")
                pdf_part.add_header("Content-Disposition", "attachment", filename=pdf_filename or f"{inc_id}.pdf")
                msg.attach(pdf_part)
            except Exception as e:
                print(f"[!] Warning attaching PDF to email: {e}")

        return msg

    def _transmit_email(self, msg: MIMEMultipart, recipients: List[str]) -> Dict[str, Any]:
        """
        Attempts live delivery via SMTP (e.g. Gmail / corporate relay).
        If SMTP is disabled or connection fails (e.g. sandbox offline), captures exact details
        and ensures the email is safely preserved in local outbox.
        """
        enabled = self.smtp_config.get("enabled", False)
        host = self.smtp_config.get("host", "smtp.gmail.com")
        port = int(self.smtp_config.get("port", 587))
        user = self.smtp_config.get("username", "")
        pwd = self.smtp_config.get("password", "")
        use_tls = self.smtp_config.get("use_tls", True)
        use_ssl = (port == 465)
        from_addr = self.smtp_config.get("from_email", self.soc_email)

        if not enabled:
            return {
                "status": "SPOOLED_LOCALLY",
                "delivered": False,
                "details": "Email compiled and preserved in local EDR outbox (.eml and .json). Enable live SMTP in settings to relay externally."
            }

        if not pwd or not pwd.strip():
            return {
                "status": "SPOOLED_OFFLINE",
                "delivered": False,
                "details": "Google App Password required: Please enter your 16-character Google App Password in 'Google App Password / Token' and click Save. Email safely preserved in outbox (.eml & .json)."
            }

        try:
            if use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=8)
            else:
                server = smtplib.SMTP(host, port, timeout=8)
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)

            if user and pwd:
                server.login(user, pwd)

            server.sendmail(from_addr, recipients, msg.as_string())
            server.quit()
            return {
                "status": "DELIVERED_VIA_SMTP",
                "delivered": True,
                "details": f"Successfully transmitted live alert email via SMTP relay ({host}:{port}) to {', '.join(recipients)}"
            }
        except smtplib.SMTPAuthenticationError as auth_err:
            return {
                "status": "SPOOLED_OFFLINE",
                "delivered": False,
                "details": f"Gmail Authentication Error: Invalid Google App Password. Please generate a 16-character password from https://myaccount.google.com/apppasswords ({auth_err}). Email safely spooled."
            }
        except Exception as ex:
            err_msg = str(ex)
            if "530" in err_msg or "Authentication Required" in err_msg:
                friendly = "Gmail Authentication Required: Please enter your 16-character Google App Password in the settings modal."
            elif "Temporary failure in name resolution" in err_msg:
                friendly = "DNS / Network Offline: Host unable to resolve smtp.gmail.com."
            elif "Network is unreachable" in err_msg:
                friendly = "Network Unreachable: Check outbound network connectivity."
            else:
                friendly = f"SMTP error: {err_msg}"
            return {
                "status": "SPOOLED_OFFLINE",
                "delivered": False,
                "details": f"{friendly} (Email safely archived in local EDR outbox)."
            }

    def dispatch_incident_email(
        self,
        report_data: Dict[str, Any],
        is_simulation: bool = False,
        scenario_name: Optional[str] = None,
        short_note: Optional[str] = None,
        custom_recipients: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Automatically compiles and sends an email notification to configured SOC recipients
        whenever an incident is detected or simulated.
        
        If it's a simulated drill (testing):
          - Attaches the formal forensic incident report in PDF form.
          - Explicitly marks the subject and body with: [TEST RANSOMWARE ATTACK]
          - Includes a clear short note explaining that this is a safe test simulation.
        """
        now_ts = time.time()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        inc_id = report_data.get("incident_id", f"INC-{int(now_ts)}")
        pdf_path = report_data.get("pdf_path")
        score = report_data.get("risk_score_100", 0.0)
        risk_level = report_data.get("risk_level", "Critical")

        is_sim = is_simulation or report_data.get("is_simulation", False)
        scenario = scenario_name or report_data.get("scenario", "Ransomware Threat Sample")

        # Fallback check for PDF on disk if not provided
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if not pdf_path or not os.path.exists(pdf_path):
            candidate_pdf = os.path.join(base_dir, "reports", f"{inc_id}.pdf")
            if os.path.exists(candidate_pdf):
                pdf_path = candidate_pdf

        # Determine Recipients
        if custom_recipients:
            if isinstance(custom_recipients, str):
                recipients = [r.strip() for r in custom_recipients.split(",") if r.strip()]
            else:
                recipients = [str(r).strip() for r in custom_recipients if str(r).strip()]
        else:
            recipients = [self.soc_email] + [e for e in self.secondary_emails if e != self.soc_email]

        # Determine Subject, Indicator, and Short Note
        if is_sim:
            subject = f"[TEST RANSOMWARE ATTACK] Forensic Incident Report Attached: {inc_id} ({scenario})"
            indicator_label = "TEST RANSOMWARE ATTACK (SIMULATED DRILL)"
            default_note = (
                f"Test ransomware attack drill executed successfully ({scenario}). "
                f"This simulated exercise validated multi-vector early detection, canary tripwires, "
                f"and automated containment. No user data was damaged. "
                f"The complete forensic incident report is attached in PDF format for SecOps review."
            )
        else:
            subject = f"🚨 [LIVE RANSOMWARE INCIDENT DETECTED] Host Containment Activated: {inc_id} (Score: {score}/100)"
            indicator_label = "LIVE ADVERSARY INCIDENT DETECTED"
            default_note = (
                f"CRITICAL: Active ransomware behavior detected on host (Score: {score}/100 - {risk_level}). "
                f"Automated containment has terminated flagged malicious processes and isolated endpoint network. "
                f"The complete forensic incident report is attached in PDF format."
            )

        note = short_note or default_note

        # Verify PDF attachment
        has_pdf = False
        pdf_size_bytes = 0
        pdf_filename = f"{inc_id}.pdf"
        if pdf_path and os.path.exists(pdf_path):
            has_pdf = True
            pdf_size_bytes = os.path.getsize(pdf_path)

        email_id = f"EMAIL-{int(now_ts * 1000)}"

        # Build full RFC-822 MIME message
        mime_msg = self._build_mime_email(
            recipients=recipients,
            subject=subject,
            inc_id=inc_id,
            indicator_label=indicator_label,
            note=note,
            score=score,
            risk_level=risk_level,
            scenario=scenario,
            is_sim=is_sim,
            pdf_path=pdf_path if has_pdf else None,
            pdf_filename=pdf_filename if has_pdf else None
        )

        # Save .eml file in outgoing spool directory (reports/sent_emails/)
        emails_dir = os.path.join(base_dir, "reports", "sent_emails")
        os.makedirs(emails_dir, exist_ok=True)
        eml_file_path = os.path.join(emails_dir, f"{email_id}.eml")
        try:
            with open(eml_file_path, "wb") as f:
                f.write(mime_msg.as_bytes())
        except Exception as e:
            print(f"[!] Warning saving RFC-822 .eml message to outbox: {e}")

        # Attempt transmission (live SMTP or local spool)
        tx_result = self._transmit_email(mime_msg, recipients)

        # Build email record
        email_record = {
            "id": email_id,
            "incident_id": inc_id,
            "timestamp": timestamp,
            "from": f"{self.smtp_config.get('from_name')} <{self.smtp_config.get('from_email')}>",
            "to": recipients,
            "subject": subject,
            "is_simulation": is_sim,
            "indicator": indicator_label,
            "short_note": note,
            "risk_score": score,
            "risk_level": risk_level,
            "scenario": scenario,
            "has_pdf_attachment": has_pdf,
            "pdf_filename": pdf_filename if has_pdf else None,
            "pdf_size_bytes": pdf_size_bytes,
            "eml_file": f"{email_id}.eml",
            "eml_path": eml_file_path,
            "delivery_status": tx_result["status"],
            "delivery_details": tx_result["details"],
            "delivered_live": tx_result["delivered"],
            "status": "SENT"
        }

        # Save metadata JSON companion
        eml_json_path = os.path.join(emails_dir, f"{email_id}.json")
        try:
            with open(eml_json_path, "w", encoding="utf-8") as f:
                json.dump(email_record, f, indent=2)
        except Exception as e:
            print(f"[!] Warning saving email JSON record to outbox: {e}")

        # Also log to sent_notifications for real-time telemetry stream
        notif_payload = {
            "id": email_record["id"],
            "timestamp": timestamp,
            "title": f"📧 [AUTOMATIC INCIDENT EMAIL] {subject}",
            "severity": "CRITICAL" if not is_sim else "HIGH",
            "channel": f"EMAIL -> {', '.join(recipients[:2])}",
            "admin_contact": self.admin_name,
            "recipients": recipients,
            "is_email": True,
            "is_simulation": is_sim,
            "short_note": note,
            "pdf_attached": has_pdf,
            "delivery_status": tx_result["status"],
            "delivery_details": tx_result["details"],
            "details": {
                "incident_id": inc_id,
                "email_to": recipients,
                "subject": subject,
                "short_note": note,
                "pdf_attached": has_pdf,
                "pdf_filename": pdf_filename if has_pdf else None,
                "scenario": scenario,
                "delivery_status": tx_result["status"]
            },
            "status": "DISPATCHED"
        }

        with self._lock:
            self.sent_notifications.append(notif_payload)
            if len(self.sent_notifications) > 100:
                self.sent_notifications.pop(0)

        # Send Webhook alert companion asynchronously
        threading.Thread(target=self._send_webhook, args=(notif_payload,), daemon=True).start()

        return email_record

    def get_sent_emails(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns dispatched emails from the outbox spool."""
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        emails_dir = os.path.join(base_dir, "reports", "sent_emails")
        results = []
        if os.path.exists(emails_dir):
            for fname in sorted(os.listdir(emails_dir), reverse=True):
                if fname.endswith(".json"):
                    try:
                        with open(os.path.join(emails_dir, fname), "r", encoding="utf-8") as f:
                            results.append(json.load(f))
                    except Exception:
                        pass
        return results[:limit]

    def dispatch_alert(self, title: str, severity: str, details: Dict[str, Any], force: bool = False,
                       custom_recipients: Optional[List[str]] = None,
                       custom_channel: Optional[str] = None,
                       custom_admin: Optional[str] = None) -> Dict[str, Any]:
        """
        Dispatches an emergency alert if not in cooldown, or if force=True.
        Accepts optional recipient/channel/admin overrides.
        """
        now = time.time()
        if not force and (now - self.last_alert_time) < self.cooldown_sec:
            return {"status": "SKIPPED_COOLDOWN", "title": title}

        self.last_alert_time = now
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Determine active recipients
        all_recipients: List[str] = []
        if custom_recipients:
            if isinstance(custom_recipients, str):
                all_recipients = [r.strip() for r in custom_recipients.split(",") if r.strip()]
            else:
                all_recipients = [str(r).strip() for r in custom_recipients if str(r).strip()]
        else:
            all_recipients = [self.soc_email] + [e for e in self.secondary_emails if e != self.soc_email]

        channel = custom_channel or self.channel
        admin_contact = custom_admin or self.admin_name

        payload = {
            "id": f"NOTIF-{int(now * 1000)}",
            "timestamp": timestamp,
            "title": title,
            "severity": severity.upper(),
            "channel": channel,
            "admin_contact": admin_contact,
            "phone_sms": self.phone_sms,
            "recipients": all_recipients,
            "details": details,
            "status": "DISPATCHED"
        }

        with self._lock:
            self.sent_notifications.append(payload)
            if len(self.sent_notifications) > 100:
                self.sent_notifications.pop(0)

        # Attempt webhook delivery asynchronously or non-blocking
        threading.Thread(target=self._send_webhook, args=(payload,), daemon=True).start()

        return payload

    def _send_webhook(self, payload: Dict[str, Any]):
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                pass
        except Exception:
            # Local loopback or simulation catch
            pass

    def get_notification_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.sent_notifications[-limit:])
