const MODAL_TEMPLATES = {
  "reportModal": "<div aria-hidden=\"true\" aria-labelledby=\"reportModalLabel\" class=\"modal fade\" id=\"reportModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-xl modal-dialog-scrollable\">\n<div class=\"modal-content bg-dark text-light border-secondary\">\n<div class=\"modal-header border-secondary\">\n<h5 class=\"modal-title\" id=\"reportModalLabel\">\n<i class=\"fa-solid fa-file-shield text-danger me-2\"></i>Forensic Incident Report\n                    </h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-0\">\n<iframe id=\"reportFrame\" src=\"about:blank\" style=\"width: 100%; height: 650px; border: none;\"></iframe>\n</div>\n<div class=\"modal-footer border-secondary d-flex justify-content-between\">\n<div>\n<a class=\"btn btn-danger btn-sm me-2\" href=\"#\" id=\"downloadPdfBtn\">\n<i class=\"fa-solid fa-file-pdf me-1\"></i> Download PDF\n                        </a>\n<a class=\"btn btn-outline-info btn-sm me-2\" href=\"#\" id=\"downloadMdBtn\" target=\"_blank\">\n<i class=\"fa-solid fa-file-code me-1\"></i> View Markdown\n                        </a>\n<button class=\"btn btn-outline-light btn-sm\" onclick=\"printReportIframe()\" type=\"button\">\n<i class=\"fa-solid fa-print me-1\"></i> Print / Save as PDF\n                        </button>\n</div>\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n</div>\n</div>\n</div>\n</div>",
  "eventDetailModal": "<div aria-hidden=\"true\" aria-labelledby=\"eventDetailLabel\" class=\"modal fade\" id=\"eventDetailModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-lg\">\n<div class=\"modal-content bg-dark text-light border-info\">\n<div class=\"modal-header border-secondary\">\n<h5 class=\"modal-title\" id=\"eventDetailLabel\">\n<i class=\"fa-solid fa-magnifying-glass-chart text-info me-2\"></i>Telemetry Event Deep-Dive Inspector\n                    </h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body\">\n<div class=\"row g-2 mb-3\">\n<div class=\"col-sm-4\">\n<span class=\"text-secondary small d-block\">Submodule Code</span>\n<span class=\"badge bg-primary fs-6\" id=\"modalEventCode\">T2</span>\n<span class=\"text-light ms-1\" id=\"modalEventModule\">Host &amp; Process</span>\n</div>\n<div class=\"col-sm-4\">\n<span class=\"text-secondary small d-block\">Severity Rating</span>\n<span class=\"badge bg-danger fs-6\" id=\"modalEventSeverity\">CRITICAL</span>\n</div>\n<div class=\"col-sm-4\">\n<span class=\"text-secondary small d-block\">UTC Timestamp</span>\n<code class=\"text-light\" id=\"modalEventTimestamp\">2026-11-16 12:00:00</code>\n</div>\n</div>\n<div class=\"p-3 rounded bg-black border border-secondary mb-3\">\n<span class=\"text-secondary small d-block fw-bold mb-1\">Event Summary / Alert Narrative:</span>\n<h6 class=\"text-warning mb-0\" id=\"modalEventMessage\">Event description goes here</h6>\n</div>\n<span class=\"text-secondary small d-block fw-bold mb-1\">Event Payload &amp; Technical Attributes:</span>\n<pre class=\"p-3 rounded bg-black border border-secondary text-info mb-0\" id=\"modalEventJson\" style=\"max-height: 250px; overflow-y: auto;\">{}</pre>\n</div>\n<div class=\"modal-footer border-secondary\">\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n</div>\n</div>\n</div>\n</div>",
  "canaryDetailModal": "<div aria-hidden=\"true\" aria-labelledby=\"canaryDetailLabel\" class=\"modal fade\" id=\"canaryDetailModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-lg modal-dialog-centered\">\n<div class=\"modal-content bg-soc-panel text-light border-danger\">\n<div class=\"modal-header border-secondary bg-dark\">\n<h5 class=\"modal-title\" id=\"canaryDetailLabel\">\n<i class=\"fa-solid fa-feather text-danger me-2\"></i>Deception Tripwire Canary Asset Inspector\n                    </h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-4\">\n<div class=\"d-flex justify-content-between align-items-center p-3 rounded bg-black border border-secondary mb-3\">\n<div>\n<h5 class=\"text-light fw-bold mb-1\" id=\"canaryModalFilename\">q4_financial_payroll.xlsx</h5>\n<span class=\"text-secondary small\" id=\"canaryModalDesc\">Executive Compensation &amp; Bonus Ledger</span>\n</div>\n<span class=\"badge bg-success fs-6 px-3 py-2\" id=\"canaryModalStatus\">INTACT</span>\n</div>\n<!-- Attacker Forensic Attribution Box (Active when COMPROMISED) -->\n<div class=\"p-3 rounded bg-black border border-danger mb-3 d-none\" id=\"canaryModalAttackerBox\">\n<div class=\"d-flex justify-content-between align-items-center mb-2\">\n<span class=\"text-danger fw-bold small\"><i class=\"fa-solid fa-triangle-exclamation me-1\"></i>Attacking Adversary Attribution (Who Triggered It)</span>\n<span class=\"badge bg-danger\" id=\"canaryModalThreatFamily\">WannaCry 2.0</span>\n</div>\n<div class=\"row g-2 small\">\n<div class=\"col-sm-6\">\n<span class=\"text-secondary d-block\">Attacker Process Binary:</span>\n<code class=\"text-warning fw-bold fs-6\" id=\"canaryModalAttackerProc\">@WanaDecryptor@.exe</code>\n</div>\n<div class=\"col-sm-6\">\n<span class=\"text-secondary d-block\">Attacker Process PID:</span>\n<code class=\"text-light fs-6\" id=\"canaryModalAttackerPid\">52160</code>\n</div>\n<div class=\"col-sm-6\">\n<span class=\"text-secondary d-block\">Breach Timestamp (When It Happened):</span>\n<span class=\"text-info fw-bold\" id=\"canaryModalCompromisedAt\">2026-11-16 14:43:38 UTC</span>\n</div>\n<div class=\"col-sm-6\">\n<span class=\"text-secondary d-block\">Tamper Mechanism:</span>\n<span class=\"text-danger fw-bold\" id=\"canaryModalTamperType\">In-place Encryption</span>\n</div>\n</div>\n</div>\n<table class=\"table table-dark table-bordered small mb-3\">\n<tbody>\n<tr><th style=\"width: 30%;\">File Vault Path</th><td><code id=\"canaryModalPath\">/canary_vault/q4_financial_payroll.xlsx</code></td></tr>\n<tr><th>Baseline SHA-256 Hash</th><td><code class=\"text-info\" id=\"canaryModalExpectedHash\">--</code></td></tr>\n<tr><th>Current Verified Hash</th><td><code class=\"text-warning\" id=\"canaryModalCurrentHash\">--</code></td></tr>\n<tr><th>Audit Frequency</th><td>Continuous 0.5s timer + Kernel Watchdog filesystem notifications</td></tr>\n<tr><th>False Positive Rate</th><td><strong class=\"text-success\">0.00% Guaranteed</strong> (Decoy never accessed by benign users)</td></tr>\n<tr><th>Breach Forensics</th><td id=\"canaryModalBreach\">No unauthorized modification observed.</td></tr>\n</tbody>\n</table>\n<div class=\"p-3 rounded bg-dark border border-secondary\">\n<span class=\"text-secondary small fw-bold d-block mb-1\">How This Tripwire Protects Endpoint Data:</span>\n<p class=\"small text-light mb-0\">Canary files are strategically named and positioned at high-value directory indices. When ransomware traverses the file system to encrypt documents, it accesses this decoy first. The framework detects the breach in &lt;1.3s and immediately triggers automated process termination before real user documents are reached.</p>\n</div>\n</div>\n<div class=\"modal-footer border-secondary bg-dark\">\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n<button class=\"btn btn-outline-danger btn-sm\" onclick=\"resetCanaries(); hideModalById('canaryDetailModal');\" type=\"button\">\n<i class=\"fa-solid fa-arrows-rotate me-1\"></i> Re-Arm Decoy Vault\n                    </button>\n</div>\n</div>\n</div>\n</div>",
  "telemetryVectorModal": "<div aria-hidden=\"true\" aria-labelledby=\"telemetryVectorLabel\" class=\"modal fade\" id=\"telemetryVectorModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-xl modal-dialog-centered\">\n<div class=\"modal-content bg-soc-panel text-light border-secondary\">\n<div class=\"modal-header border-secondary bg-dark d-flex justify-content-between align-items-center\">\n<div class=\"d-flex align-items-center gap-2\">\n<i class=\"fa-solid fa-network-wired text-info fs-4\" id=\"vectorModalIcon\"></i>\n<div>\n<h5 class=\"modal-title mb-0 fw-bold\" id=\"vectorModalTitle\">Telemetry Vector Inspection</h5>\n<small class=\"text-secondary\" id=\"vectorModalSub\">Multi-Vector Behavioral Stream</small>\n</div>\n</div>\n<div class=\"d-flex align-items-center gap-2\">\n<span class=\"badge fs-6 px-3 py-2\" id=\"vectorModalBadge\">0 / Normal</span>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n</div>\n<div class=\"modal-body p-4\">\n<!-- Vector Summary Alert -->\n<div class=\"p-3 rounded bg-dark border border-secondary mb-3 d-flex justify-content-between align-items-center\">\n<div class=\"d-flex align-items-center gap-3\">\n<div class=\"score-dial text-center\" style=\"min-width: 100px;\">\n<h2 class=\"display-6 fw-bold mb-0 text-info\" id=\"vectorModalMetricValue\">0</h2>\n<small class=\"text-secondary d-block\" id=\"vectorModalMetricLabel\">Metric</small>\n</div>\n<div class=\"border-start border-secondary ps-3\">\n<span class=\"badge bg-secondary mb-1\" id=\"vectorModalStatusTag\">Status: Active</span>\n<p class=\"small text-light mb-0\" id=\"vectorModalSummary\">Description of telemetry vector.</p>\n</div>\n</div>\n</div>\n<!-- Nav Tabs: Active Trigger Evidence vs What It Takes Into Consideration -->\n<ul class=\"nav nav-pills mb-3 border-bottom border-secondary pb-2\" id=\"vectorModalTabs\" role=\"tablist\">\n<li class=\"nav-item\" role=\"presentation\">\n<button class=\"nav-link active px-3 py-2 fw-bold\" data-bs-target=\"#tab-vector-evidence\" data-bs-toggle=\"pill\" id=\"tab-evidence-link\" role=\"tab\" type=\"button\">\n<i class=\"fa-solid fa-list-check me-2\"></i>Active Trigger Evidence (<span id=\"vectorEvidenceCount\">0</span>)\n                            </button>\n</li>\n<li class=\"nav-item\" role=\"presentation\">\n<button class=\"nav-link px-3 py-2 fw-bold text-light\" data-bs-target=\"#tab-vector-considerations\" data-bs-toggle=\"pill\" id=\"tab-considerations-link\" role=\"tab\" type=\"button\">\n<i class=\"fa-solid fa-brain me-2\"></i>What It Takes Into Consideration (Heuristics &amp; Formulas)\n                            </button>\n</li>\n</ul>\n<div class=\"tab-content\" id=\"vectorModalTabContent\">\n<!-- Tab 1: Live Trigger Evidence -->\n<div class=\"tab-pane fade show active\" id=\"tab-vector-evidence\" role=\"tabpanel\">\n<div id=\"vectorEvidenceContainer\">\n<div class=\"text-center py-4 text-secondary\">\n<div class=\"spinner-border text-info\" role=\"status\"></div>\n<p class=\"mt-2 small\">Loading telemetry vector evidence...</p>\n</div>\n</div>\n</div>\n<!-- Tab 2: Considerations & Heuristics -->\n<div class=\"tab-pane fade\" id=\"tab-vector-considerations\" role=\"tabpanel\">\n<div class=\"row g-3\" id=\"vectorConsiderationsContainer\">\n<!-- Dynamically populated list of rules & formulas -->\n</div>\n</div>\n</div>\n</div>\n<div class=\"modal-footer border-secondary bg-dark d-flex justify-content-between\">\n<div>\n<small class=\"text-secondary\"><i class=\"fa-solid fa-shield-halved text-success me-1\"></i>Real-time telemetry stream synchronized via WebSocket/Prometheus agent</small>\n</div>\n<div id=\"vectorModalActions\">\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n</div>\n</div>\n</div>\n</div>\n</div>",
  "processDetailModal": "<div aria-hidden=\"true\" aria-labelledby=\"processDetailLabel\" class=\"modal fade\" id=\"processDetailModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-dialog-centered modal-lg\">\n<div class=\"modal-content bg-soc-panel text-light border-secondary\">\n<div class=\"modal-header border-secondary bg-dark\">\n<h5 class=\"modal-title\" id=\"processDetailLabel\">\n<i class=\"fa-solid fa-microchip text-danger me-2\"></i>Suspicious Process Forensic Profile (T2)\n                    </h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-4\">\n<div class=\"d-flex justify-content-between align-items-center mb-3 p-3 rounded bg-dark border border-secondary\">\n<div>\n<h5 class=\"text-light fw-bold mb-1\" id=\"procModalName\">lockbit3_encryptor.exe</h5>\n<span class=\"text-secondary small\">PID: <code class=\"text-info\" id=\"procModalPid\">--</code> | PPID: <code class=\"text-secondary\" id=\"procModalPpid\">--</code> (<span id=\"procModalParent\">cmd_runner</span>)</span>\n</div>\n<span class=\"badge bg-danger fs-6 px-3 py-2\" id=\"procModalStatus\">SUSPICIOUS (ACTIVE)</span>\n</div>\n<table class=\"table table-dark table-striped table-bordered small\">\n<tbody>\n<tr><th style=\"width: 28%;\">Executable Path</th><td><code id=\"procModalExe\">/tmp/lockbit3_encryptor.exe</code></td></tr>\n<tr><th>Command Line Arguments</th><td><code class=\"text-warning\" id=\"procModalCmdline\">--</code></td></tr>\n<tr><th>Composite Threat Score</th><td><span class=\"badge bg-danger fs-6\" id=\"procModalThreatScore\">0.94 / 1.00</span></td></tr>\n<tr><th>Process Metrics</th><td>CPU: <span class=\"text-info fw-bold\" id=\"procModalCpu\">18.5%</span> | Memory RSS: <span class=\"text-light fw-bold\" id=\"procModalMem\">45 MB</span></td></tr>\n<tr><th>Behavioral Anomaly Flags</th><td id=\"procModalFlags\"><span class=\"badge bg-danger me-1\">Execution from /tmp</span></td></tr>\n<tr><th>User &amp; Security Context</th><td><code class=\"text-secondary\" id=\"procModalUser\">root</code> \u2014 Elevated privileges</td></tr>\n</tbody>\n</table>\n<div class=\"p-3 rounded bg-dark border border-secondary\">\n<span class=\"text-secondary small fw-bold d-block mb-1\">EDR Behavioral Containment Protocol:</span>\n<p class=\"small text-light mb-0\">This process was flagged by T2 Ancestry Monitoring due to anomalous execution directory, high CPU cryptographic burst patterns, and API shadow copy suppression. Clicking <strong>Terminate Process</strong> sends an immediate kernel SIGKILL to prevent further encryption.</p>\n</div>\n</div>\n<div class=\"modal-footer border-secondary\">\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n<button class=\"btn btn-danger btn-sm\" id=\"procModalKillBtn\" onclick=\"killModalProcess();\" type=\"button\">\n<i class=\"fa-solid fa-skull me-1\"></i> Terminate Process (SIGKILL)\n                    </button>\n</div>\n</div>\n</div>\n</div>",
  "riskFormulaModal": "<div aria-hidden=\"true\" aria-labelledby=\"riskFormulaLabel\" class=\"modal fade\" id=\"riskFormulaModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable\">\n<div class=\"modal-content bg-dark text-light border-warning shadow-lg\">\n<div class=\"modal-header border-secondary bg-soc-header\">\n<h5 class=\"modal-title fw-bold\" id=\"riskFormulaLabel\">\n<i class=\"fa-solid fa-calculator text-warning me-2\"></i>Composite Risk Index Calculation Engine &amp; Mathematical Formula\n                    </h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-4\">\n<!-- Top Alert: Formula & Equation -->\n<div class=\"alert p-3 mb-3 rounded\" style=\"background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(245, 158, 11, 0.4);\">\n<div class=\"d-flex justify-content-between align-items-center mb-2\">\n<span class=\"badge px-3 py-1 fs-6\" style=\"background:#f59e0b; color:#0f172a; font-weight:800;\">\n<i class=\"fa-solid fa-square-root-variable me-1\"></i> MATHEMATICAL FORMULATION\n                            </span>\n<span class=\"text-info fw-bold\" id=\"rf-weighted-sum-badge\">\n                                Live Sum: <span class=\"text-warning fs-5 fw-bold\" id=\"rf-weighted-sum\">0.0</span> / 125.0\n                            </span>\n</div>\n<p class=\"small text-light mb-2\">\n                            The Early Warning Framework evaluates global ransomware intrusion probability using a composite multi-vector scoring function. Each telemetry submodule yields a normalized signal score $S_i \\in [0.0, 1.0]$, weighted by its impact multiplier $W_i$:\n                        </p>\n<div class=\"p-2 rounded bg-black border border-secondary text-center my-2 font-monospace\">\n<span class=\"text-warning fw-bold fs-5\">R<sub>index</sub> = min(100.0, \u00a0(\u03a3<sub>i=1..7</sub> [ W<sub>i</sub> \u00d7 S<sub>i</sub> ] / 125.0) \u00d7 100)</span>\n</div>\n<div class=\"small text-secondary mt-2 d-flex justify-content-between flex-wrap gap-2 pt-2 border-top border-secondary\">\n<span><i class=\"fa-solid fa-circle text-success me-1\"></i><strong>Normal:</strong> 0.0 \u2264 R &lt; 40.0</span>\n<span><i class=\"fa-solid fa-circle text-info me-1\"></i><strong>Elevated:</strong> 40.0 \u2264 R &lt; 65.0</span>\n<span><i class=\"fa-solid fa-circle text-warning me-1\"></i><strong>High Alert:</strong> 65.0 \u2264 R &lt; 80.0</span>\n<span><i class=\"fa-solid fa-circle text-danger me-1\"></i><strong>Critical (Containment Armed):</strong> 80.0 \u2264 R \u2264 100.0</span>\n</div>\n</div>\n<!-- Live Breakdown Matrix Table -->\n<div class=\"card bg-dark border-secondary mb-3\">\n<div class=\"card-header bg-soc-header d-flex justify-content-between align-items-center py-2\">\n<span class=\"fw-bold small text-light\"><i class=\"fa-solid fa-table-list text-info me-2\"></i>Real-Time Telemetry Factor Weights Matrix</span>\n<span class=\"badge bg-secondary small\">Total Capacity: 125.0 Weight Points</span>\n</div>\n<div class=\"card-body p-0 table-responsive\">\n<table class=\"table table-dark table-hover mb-0 small align-middle\">\n<thead>\n<tr class=\"border-secondary text-secondary\">\n<th>Telemetry Vector</th>\n<th>MITRE ATT&amp;CK</th>\n<th>Max Weight</th>\n<th>Live Real-Time Telemetry State</th>\n<th class=\"text-end\">Contributed Points</th>\n</tr>\n</thead>\n<tbody>\n<tr>\n<td>\n<i class=\"fa-solid fa-file-shield text-danger me-2\"></i>\n<strong>Canary Tripwire Vault</strong> (T7)\n                                        </td>\n<td><span class=\"badge bg-danger\">T1486</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 35</span></td>\n<td><span class=\"text-success fw-bold\" id=\"rf-canary-val\">INTACT (0 Breaches)</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-canary-pts\">+0.0 / 35.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-chart-area text-info me-2\"></i>\n<strong>Shannon Entropy Burst</strong> (T3)\n                                        </td>\n<td><span class=\"badge bg-danger\">T1486</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 25</span></td>\n<td><span class=\"text-info fw-bold\" id=\"rf-entropy-val\">0.00 bits/byte</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-entropy-pts\">+0.0 / 25.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-shield-halved text-warning me-2\"></i>\n<strong>Defense Evasion / VSS</strong> (T6)\n                                        </td>\n<td><span class=\"badge bg-danger\">T1490</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 20</span></td>\n<td><span class=\"text-light fw-bold\" id=\"rf-recovery-val\">0 VSS delete cmds</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-recovery-pts\">+0.0 / 20.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-file-signature text-light me-2\"></i>\n<strong>High-Rate File Renames</strong> (T3)\n                                        </td>\n<td><span class=\"badge bg-secondary\">T1486</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 15</span></td>\n<td><span class=\"text-light fw-bold\" id=\"rf-renames-val\">0.0 renames/s</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-renames-pts\">+0.0 / 15.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-microchip text-primary me-2\"></i>\n<strong>Malicious Process Ancestry</strong> (T2)\n                                        </td>\n<td><span class=\"badge bg-secondary\">T1059</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 10</span></td>\n<td><span class=\"text-light fw-bold\" id=\"rf-process-val\">Score 0.00 / 1.00</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-process-pts\">+0.0 / 10.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-network-wired text-info me-2\"></i>\n<strong>C2 Beacon &amp; Lateral Movement</strong> (T5)\n                                        </td>\n<td><span class=\"badge bg-secondary\">T1071</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 10</span></td>\n<td><span class=\"text-light fw-bold\" id=\"rf-network-val\">0 C2 | 0 Lateral</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-network-pts\">+0.0 / 10.0</span></td>\n</tr>\n<tr>\n<td>\n<i class=\"fa-solid fa-user-lock text-warning me-2\"></i>\n<strong>Identity &amp; LSASS Access</strong> (T4)\n                                        </td>\n<td><span class=\"badge bg-secondary\">T1003</span></td>\n<td><span class=\"badge bg-dark border border-warning text-warning\">W = 10</span></td>\n<td><span class=\"text-light fw-bold\" id=\"rf-auth-val\">0 LSASS | 0 Failed</span></td>\n<td class=\"text-end\"><span class=\"badge bg-secondary\" id=\"rf-auth-pts\">+0.0 / 10.0</span></td>\n</tr>\n</tbody>\n</table>\n</div>\n</div>\n<!-- Explanatory Policy Callout -->\n<div class=\"p-3 rounded bg-dark border border-secondary small\">\n<div class=\"d-flex align-items-center mb-1 text-warning fw-bold\">\n<i class=\"fa-solid fa-shield-virus me-2\"></i> Automated Containment Trigger Logic:\n                        </div>\n<p class=\"text-secondary mb-0\">\n                            When the composite score $R_{\\text{index}} \\ge 80.0$, the automated containment loop triggers immediate process termination (SIGKILL), host network quarantine (dropping outbound C2 &amp; SMB), directory write revocation, and emergency dispatch without waiting for human intervention.\n                        </p>\n</div>\n</div>\n<div class=\"modal-footer border-secondary bg-soc-header d-flex justify-content-between\">\n<button class=\"btn btn-outline-warning btn-sm\" onclick=\"hideModalById('riskFormulaModal'); scrollToSimulationSuite();\" type=\"button\">\n<i class=\"fa-solid fa-vial me-1\"></i> Test in Ransomware Simulation Suite\n                    </button>\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n</div>\n</div>\n</div>\n</div>",
  "notifyAdminModal": "<div aria-hidden=\"true\" aria-labelledby=\"notifyAdminModalLabel\" class=\"modal fade\" id=\"notifyAdminModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable\">\n<div class=\"modal-content bg-soc-card border-secondary text-light\">\n<div class=\"modal-header border-secondary bg-soc-header d-flex justify-content-between align-items-center\">\n<div class=\"d-flex align-items-center\">\n<i class=\"fa-solid fa-bell text-warning fs-4 me-2\"></i>\n<div>\n<h5 class=\"modal-title fw-bold mb-0\" id=\"notifyAdminModalLabel\">Notify SOC Admin &amp; Alert Recipient Settings</h5>\n<small class=\"text-secondary\">Configure alert recipients, SMTP relay, and inspect automated incident emails (Test &amp; Real)</small>\n</div>\n</div>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-4\" style=\"background: #0f172a;\">\n<!-- Recipient Configuration Card -->\n<div class=\"card bg-dark border-secondary mb-3 shadow-sm\">\n<div class=\"card-header bg-black border-secondary py-2 d-flex justify-content-between align-items-center\">\n<span class=\"fw-bold text-warning small\">\n<i class=\"fa-solid fa-users me-1\"></i> Alert Recipients &amp; Contact Channels (Whom to Send Alert)\n                            </span>\n<span class=\"badge bg-secondary\" id=\"notifConfigStatusBadge\">Configured</span>\n</div>\n<div class=\"card-body\">\n<div class=\"row g-3\">\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-envelope text-info me-1\"></i>Primary SOC Email:\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifPrimaryEmail\" placeholder=\"e.g. ankitnim227@gmail.com\" type=\"email\" value=\"ankitnim227@gmail.com\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Primary mailbox receiving alerts &amp; PDF incident reports.</small>\n</div>\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-user-shield text-primary me-1\"></i>SOC Admin / Incident Commander:\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifAdminName\" placeholder=\"e.g. Chief Information Security Officer\" type=\"text\" value=\"Chief Information Security Officer\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Designated on-call lead engineer or incident commander.</small>\n</div>\n<div class=\"col-md-12\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-envelopes-bulk text-warning me-1\"></i>Secondary / Escalation Emails (CC):\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifSecondaryEmails\" placeholder=\"e.g. soc-tier3@enterprise.org, ciso-direct@enterprise.org\" type=\"text\" value=\"soc-tier3@enterprise.org, ciso-direct@enterprise.org\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Comma-separated list of escalation addresses alerted on critical incidents.</small>\n</div>\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-hashtag text-success me-1\"></i>Broadcast Channel / Slack / Teams:\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifBroadcastChannel\" placeholder=\"e.g. #critical-secops-war-room\" type=\"text\" value=\"#critical-secops-war-room\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Internal chat room or SIEM broadcast topic.</small>\n</div>\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-phone-volume text-danger me-1\"></i>Emergency SMS / On-Call Hotline:\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifPhone\" placeholder=\"e.g. +1-888-999-SECOPS\" type=\"text\" value=\"+1-888-999-SECOPS\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Emergency bridge number or SMS automated alert gateway.</small>\n</div>\n<div class=\"col-md-12\">\n<label class=\"form-label text-light small fw-bold mb-1\">\n<i class=\"fa-solid fa-server text-info me-1\"></i>SIEM / Webhook Receiver URL:\n                                    </label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifWebhookUrl\" placeholder=\"e.g. http://127.0.0.1:8000/api/webhook/alerts\" type=\"url\" value=\"http://127.0.0.1:8000/api/webhook/alerts\"/>\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">Automated HTTP POST endpoint for SIEM or internal webhook listener.</small>\n</div>\n</div>\n</div>\n</div>\n<!-- Live SMTP Mail Server Configuration Card -->\n<div class=\"card bg-dark border-secondary mb-3 shadow-sm\">\n<div class=\"card-header bg-black border-secondary py-2 d-flex justify-content-between align-items-center\">\n<span class=\"fw-bold text-info small\">\n<i class=\"fa-solid fa-envelope-circle-check me-1\"></i> Live SMTP Relay &amp; Email Dispatch Triggers\n</span>\n<div class=\"form-check form-switch mb-0\">\n<input class=\"form-check-input\" id=\"notifSmtpEnabled\" type=\"checkbox\"/>\n<label class=\"form-check-label text-light small\" for=\"notifSmtpEnabled\">Enable Live SMTP Relay</label>\n</div>\n</div>\n<div class=\"card-body\">\n<div class=\"row g-2\">\n<div class=\"col-md-5\">\n<label class=\"form-label text-light small fw-bold mb-1\">SMTP Relay Host:</label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifSmtpHost\" placeholder=\"smtp.gmail.com\" type=\"text\" value=\"smtp.gmail.com\"/>\n</div>\n<div class=\"col-md-3\">\n<label class=\"form-label text-light small fw-bold mb-1\">Port:</label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifSmtpPort\" placeholder=\"587\" type=\"number\" value=\"587\"/>\n</div>\n<div class=\"col-md-4 d-flex align-items-end\">\n<div class=\"form-check mb-2\">\n<input checked=\"\" class=\"form-check-input\" id=\"notifSmtpTls\" type=\"checkbox\"/>\n<label class=\"form-check-label text-secondary small\" for=\"notifSmtpTls\">STARTTLS Encryption</label>\n</div>\n</div>\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">SMTP Username / Email:</label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifSmtpUser\" placeholder=\"e.g. ankitnim227@gmail.com\" type=\"email\" value=\"ankitnim227@gmail.com\"/>\n</div>\n<div class=\"col-md-6\">\n<label class=\"form-label text-light small fw-bold mb-1\">Google App Password / Token:</label>\n<input class=\"form-control form-control-sm bg-black border-secondary text-light\" id=\"notifSmtpPassword\" placeholder=\"16-character Google App Password\" type=\"password\"/>\n</div>\n</div>\n<div class=\"d-flex justify-content-between align-items-center mt-3 pt-2 border-top border-secondary flex-wrap gap-2\">\n<small class=\"text-secondary\" style=\"font-size: 0.72rem;\">\n<i class=\"fa-solid fa-circle-info text-info me-1\"></i>For Gmail: enter your 16-character <strong>Google App Password</strong>. When disabled or offline, emails are safely archived in <code>reports/sent_emails/</code> as full <code>.eml</code> files.\n</small>\n<div class=\"d-flex gap-2\">\n<button class=\"btn btn-outline-info btn-sm text-nowrap\" id=\"testEmailBtn\" onclick=\"testEmailDelivery('test')\" type=\"button\">\n<i class=\"fa-solid fa-flask-vial me-1\"></i>Send Test Email (Simulation)\n</button>\n<button class=\"btn btn-outline-danger btn-sm text-nowrap\" id=\"realAlertBtn\" onclick=\"testEmailDelivery('real')\" type=\"button\">\n<i class=\"fa-solid fa-radiation me-1\"></i>Send Sample Live Alert Email\n</button>\n</div>\n</div>\n</div>\n</div>\n<!-- Automated Incident Email & PDF Report Dispatch Policy -->\n<div class=\"alert alert-info py-2 px-3 mb-3 small d-flex align-items-center\" style=\"background: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.3); color: #7dd3fc;\">\n<i class=\"fa-solid fa-paper-plane fs-4 me-3 text-info\"></i>\n<div>\n<strong>Automatic Email Policy:</strong>\n                            &bull; <strong>Testing / Simulations:</strong> Dispatches with <span class=\"badge\" style=\"background:#7c3aed; color:#fff;\">[TEST RANSOMWARE ATTACK]</span> and the drill verification note.<br>\n                            &bull; <strong>Real Threats:</strong> Continuous background detection automatically dispatches <span class=\"badge bg-danger\">🚨 [LIVE RANSOMWARE INCIDENT]</span> upon containment.<br>\n                            &bull; <strong>PDF Attached:</strong> In both cases, the official NIST SP 800-61 forensic report is attached in genuine PDF format.\n                        </div>\n</div>\n<!-- Outbox & Email Audit History -->\n<div class=\"card bg-dark border-secondary mb-0 shadow-sm\">\n<div class=\"card-header bg-black border-secondary py-2 d-flex justify-content-between align-items-center\">\n<span class=\"fw-bold text-light small\">\n<i class=\"fa-solid fa-inbox text-info me-1\"></i> Dispatched Email Alerts &amp; Outbox Audit Log\n</span>\n<button class=\"btn btn-outline-secondary btn-sm py-0 px-2\" onclick=\"loadDispatchedEmailsLog()\" type=\"button\">\n<i class=\"fa-solid fa-rotate me-1\"></i>Refresh Outbox\n</button>\n</div>\n<div class=\"card-body p-2\" id=\"notifEmailsContainer\" style=\"max-height: 220px; overflow-y: auto;\">\n<div class=\"text-secondary small text-center py-2\">Loading email audit log...</div>\n</div>\n</div>\n</div>\n<div class=\"modal-footer border-secondary bg-soc-header d-flex justify-content-between\">\n<button class=\"btn btn-outline-secondary btn-sm\" onclick=\"resetNotifyConfigToDefaults()\" type=\"button\">\n<i class=\"fa-solid fa-rotate-left me-1\"></i>Reset Defaults\n                    </button>\n<div class=\"d-flex gap-2\">\n<button class=\"btn btn-secondary btn-sm\" data-bs-dismiss=\"modal\" type=\"button\">Close</button>\n<button class=\"btn btn-primary btn-sm fw-bold px-3 shadow\" onclick=\"saveNotifyConfig(true)\" type=\"button\">\n<i class=\"fa-solid fa-floppy-disk me-1\"></i>Save Recipient Details\n                        </button>\n</div>\n</div>\n</div>\n</div>\n</div>",
  "simulationEmailPromptModal": "<div aria-hidden=\"true\" aria-labelledby=\"simulationEmailPromptModalLabel\" class=\"modal fade\" id=\"simulationEmailPromptModal\" tabindex=\"-1\">\n<div class=\"modal-dialog modal-dialog-centered\">\n<div class=\"modal-content bg-soc-panel text-light border-warning shadow-lg\" style=\"background: #0f172a; border: 1px solid #f59e0b;\">\n<div class=\"modal-header border-secondary bg-dark\">\n<h5 class=\"modal-title fw-bold text-light\" id=\"simulationEmailPromptModalLabel\">\n<i class=\"fa-solid fa-envelope-circle-check text-warning me-2\"></i>Dispatch Test Alert Email?\n</h5>\n<button aria-label=\"Close\" class=\"btn-close btn-close-white\" data-bs-dismiss=\"modal\" type=\"button\"></button>\n</div>\n<div class=\"modal-body p-4\">\n<div class=\"d-flex align-items-center mb-3 p-3 rounded bg-dark border border-secondary\">\n<i class=\"fa-solid fa-vial-virus text-warning fs-1 me-3\"></i>\n<div>\n<h6 class=\"text-light fw-bold mb-1\" id=\"simPromptScenarioName\">Test Ransomware Attack Simulation</h6>\n<span class=\"text-secondary small\">Simulation completed &bull; Report ID: <code class=\"text-info\" id=\"simPromptIncidentId\">SIM-INC-xxxx</code></span>\n</div>\n</div>\n<p class=\"small text-light mb-3\">\nA simulated adversary attack drill has just finished executing. The system generated a formal forensic report with an attached <strong>NIST SP 800-61 / MITRE ATT&amp;CK Technical PDF</strong>.\n</p>\n<div class=\"p-3 rounded bg-black border border-secondary mb-3 small\">\n<div class=\"d-flex justify-content-between mb-1\">\n<span class=\"text-secondary\">Designated Recipient:</span>\n<strong class=\"text-info\" id=\"simPromptRecipient\">ankitnim227@gmail.com</strong>\n</div>\n<div class=\"d-flex justify-content-between mb-1\">\n<span class=\"text-secondary\">Subject Classification:</span>\n<span class=\"badge\" style=\"background:#7c3aed; color:#fff;\">[TEST RANSOMWARE ATTACK]</span>\n</div>\n<div class=\"d-flex justify-content-between\">\n<span class=\"text-secondary\">Forensic Technical Dossier:</span>\n<span class=\"text-warning\"><i class=\"fa-solid fa-file-pdf me-1\"></i><span id=\"simPromptPdfName\">SIM-INC-xxxx.pdf</span></span>\n</div>\n</div>\n<div class=\"alert alert-dark border-secondary py-2 px-3 small text-secondary mb-0\">\n<i class=\"fa-solid fa-circle-question text-info me-1\"></i>\n<strong>Would you like to send this test report email now?</strong> You can transmit it to your mailbox, or skip sending to keep the report archived locally only.\n</div>\n</div>\n<div class=\"modal-footer border-secondary bg-dark d-flex justify-content-between\">\n<button class=\"btn btn-outline-secondary btn-sm\" data-bs-dismiss=\"modal\" onclick=\"skipSimulationEmail()\" type=\"button\">\n<i class=\"fa-solid fa-xmark me-1\"></i> Skip (Do Not Send)\n</button>\n<button class=\"btn btn-primary btn-sm fw-bold px-3 shadow\" id=\"btnConfirmSendSimEmail\" onclick=\"confirmDispatchSimulationEmail()\" type=\"button\">\n<i class=\"fa-solid fa-paper-plane me-1\"></i> Send Test Email Now\n</button>\n</div>\n</div>\n</div>\n</div>"
};

function ensureModal(modalId) {
    let el = document.getElementById(modalId);
    if (!el && MODAL_TEMPLATES[modalId]) {
        const div = document.createElement('div');
        div.innerHTML = MODAL_TEMPLATES[modalId].trim();
        el = div.firstElementChild;
        document.body.appendChild(el);
        // Bind dismiss buttons
        el.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.addEventListener('click', function() {
                hideModalById(modalId);
            });
        });
    }
    return el;
}


// Central SOC Command Center JavaScript Controller - Enterprise Behavioral EDR

let entropyChart = null;
const entropyDataPoints = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const entropyLabels = Array(15).fill('');
let currentActiveIncidentId = null;

let currentTelemetryEvents = [];
let currentCanaries = [];
let currentProcesses = [];
let currentModalProcPid = null;
let currentModalProcName = '';
let baselinePollInterval = null;
let benchmarkPollInterval = null;
let lastBenchmarkRunId = null;

document.addEventListener('DOMContentLoaded', () => {
    initEntropyChart();
    fetchTelemetry();
    fetchReports();
    pollBaselineStatus();
    updateScenarioDescription();

    // Wire up modal dismiss buttons for fallback modal handling
    document.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
        btn.addEventListener('click', function() {
            const modal = this.closest('.modal');
            if (modal) hideModalById(modal.id);
        });
    });

    // Poll telemetry every 1.5 seconds for live real-time response
    setInterval(fetchTelemetry, 1500);
    setInterval(fetchReports, 5000);
});

function initEntropyChart() {
    try {
        const canvas = document.getElementById('entropyMiniChart');
        if (!canvas) return;
        if (typeof Chart !== 'undefined') {
            const ctx = canvas.getContext('2d');
            entropyChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: entropyLabels,
                    datasets: [{
                        label: 'Entropy (bits/byte)',
                        data: entropyDataPoints,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        pointRadius: 2,
                        pointHoverRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => `Entropy: ${ctx.parsed.y.toFixed(2)} bits/byte`
                            }
                        }
                    },
                    scales: {
                        y: {
                            min: 0,
                            max: 8.0,
                            grid: { color: 'rgba(255, 255, 255, 0.08)' },
                            ticks: { color: '#cbd5e1', font: { size: 10 } }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { display: false }
                        }
                    }
                }
            });
        } else {
            console.warn("Chart.js not loaded, using native canvas fallback");
            drawNativeCanvasEntropy();
        }
    } catch (e) {
        console.error("Error initializing entropy chart:", e);
        drawNativeCanvasEntropy();
    }
}

function drawNativeCanvasEntropy() {
    const canvas = document.getElementById('entropyMiniChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width = canvas.parentElement ? canvas.parentElement.clientWidth : 280;
    const h = canvas.height = canvas.parentElement ? canvas.parentElement.clientHeight : 75;

    ctx.clearRect(0, 0, w, h);

    // Draw background grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(0, h * 0.25); ctx.lineTo(w, h * 0.25);
    ctx.moveTo(0, h * 0.5); ctx.lineTo(w, h * 0.5);
    ctx.moveTo(0, h * 0.75); ctx.lineTo(w, h * 0.75);
    ctx.stroke();

    // Draw entropy threshold line (7.85 bits/byte)
    const threshY = h - ((7.85 / 8.0) * h);
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(0, threshY); ctx.lineTo(w, threshY);
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw entropy waveform
    const step = w / Math.max(1, entropyDataPoints.length - 1);
    ctx.beginPath();
    for (let i = 0; i < entropyDataPoints.length; i++) {
        const val = entropyDataPoints[i];
        const x = i * step;
        const y = h - ((val / 8.0) * h);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    const lastVal = entropyDataPoints[entropyDataPoints.length - 1];
    ctx.strokeStyle = lastVal >= 7.85 ? '#ef4444' : '#06b6d4';
    ctx.lineWidth = 2.5;
    ctx.stroke();
}

async function fetchTelemetry() {
    try {
        const resp = await fetch('/api/telemetry');
        if (!resp.ok) return;
        const data = await resp.json();
        updateUI(data);
    } catch (e) {
        console.error("Failed to fetch telemetry:", e);
    }
}

function updateUI(data) {
    const risk = data.risk || {};
    const entropy = data.entropy || {};
    const canaries = data.canaries || [];
    const processes = data.processes || [];
    const events = data.events || [];
    const containment = data.containment_history || [];

    currentTelemetryEvents = events;
    currentCanaries = canaries;
    currentProcesses = processes;

    // 1. Update Composite Threat Score
    const score = risk.risk_score_100 || 0.0;
    const level = risk.risk_level || "Normal";
    const color = risk.badge_color || "#10b981";

    const scoreDisplay = document.getElementById('risk-score-display');
    if (scoreDisplay) {
        scoreDisplay.innerText = score.toFixed(1);
        scoreDisplay.style.color = color;
    }

    const badge = document.getElementById('risk-level-badge');
    if (badge) {
        badge.innerText = level.toUpperCase();
        badge.style.backgroundColor = color;
    }

    const pbar = document.getElementById('risk-progress-bar');
    if (pbar) {
        pbar.style.width = `${Math.min(100, Math.max(0, score))}%`;
        pbar.style.backgroundColor = color;
    }

    const policyText = document.getElementById('recommended-action-text');
    if (policyText && risk.recommended_action) {
        policyText.innerHTML = `Policy: <strong class="text-light">${risk.recommended_action}</strong>`;
    }

    // Update Network Connections Badge
    const isNetIsolated = !!(data.containment && data.containment.is_network_isolated);
    const netBadge = document.getElementById('network-status-badge');
    const netText = document.getElementById('network-status-text');
    if (netBadge && netText) {
        if (isNetIsolated) {
            netBadge.className = 'badge bg-danger text-light border border-danger animate-pulse me-3 px-3 py-2';
            netText.innerText = 'DISCONNECTED (QUARANTINED)';
        } else {
            netBadge.className = 'badge bg-success-subtle text-success border border-success me-3 px-3 py-2';
            netText.innerText = 'ONLINE';
        }
    }

    // 2. Update Alert Banner
    const banner = document.getElementById('alert-banner');
    const isAnyCanaryBreached = canaries.some(c => c.status === "COMPROMISED");
    if (isNetIsolated || score >= 50 || isAnyCanaryBreached) {
        banner.classList.remove('d-none');
        if (isNetIsolated && !isAnyCanaryBreached && score < 50) {
            document.getElementById('alert-banner-title').innerText = "⚠️ NETWORK CONNECTIONS DISCONNECTED:";
            document.getElementById('alert-banner-text').innerText = "Containment active: Endpoint connections isolated from network. Click 'Resume All Services' to restore normal baseline.";
        } else {
            document.getElementById('alert-banner-title').innerText = score >= 80 || isAnyCanaryBreached ? 
                "🚨 CRITICAL RANSOMWARE THREAT DETECTED:" : "⚠️ HIGH THREAT ALERT:";
            document.getElementById('alert-banner-text').innerText = isAnyCanaryBreached ?
                "Zero-false-positive Canary Decoy breached! All network connections disconnected. Containment active." :
                `Multi-vector threat score elevated (${score.toFixed(1)}/100). All connections disconnected & quarantined.`;
        }
    } else {
        banner.classList.add('d-none');
    }

    // 3. Update Real-time Entropy
    const currEntropy = entropy.latest_entropy || 0.0;
    document.getElementById('current-entropy-val').innerText = currEntropy.toFixed(2);
    document.getElementById('consec-entropy-hits').innerText = `${entropy.consecutive_high_entropy || 0} / 3`;

    entropyDataPoints.shift();
    entropyDataPoints.push(currEntropy);
    if (entropyChart) {
        entropyChart.data.datasets[0].borderColor = currEntropy >= 7.85 ? '#ef4444' : '#06b6d4';
        entropyChart.update('none');
    } else {
        drawNativeCanvasEntropy();
    }

    // 4. Update Deception Tripwire Vault & Canary Decoy Inventory (Merged Section)
    const breachedCanaries = canaries.filter(c => c.status === "COMPROMISED");
    const vaultBadge = document.getElementById('canary-vault-status-badge');
    if (vaultBadge) {
        if (breachedCanaries.length > 0) {
            vaultBadge.className = 'badge bg-danger animate-pulse';
            vaultBadge.innerText = `${breachedCanaries.length} TRIPWIRES BREACHED`;
        } else {
            vaultBadge.className = 'badge bg-success';
            vaultBadge.innerText = `${canaries.length} / ${canaries.length} INTACT`;
        }
    }

    const sepList = document.getElementById('canary-separate-list');
    if (sepList && canaries.length > 0) {
        sepList.innerHTML = canaries.map(c => {
            const isComp = c.status === "COMPROMISED";
            return `
                <div class="canary-tripwire-item flex-grow-1 p-1 px-2 rounded ${isComp ? 'breached' : ''}" onclick="openCanaryDetailModal('${escapeHtml(c.filename)}')" title="Click to view decoy asset details" style="cursor: pointer; background: rgba(15, 23, 42, 0.6); border: 1px solid ${isComp ? '#ef4444' : '#334155'};">
                    <div class="d-flex justify-content-between align-items-center gap-2">
                        <div class="text-truncate">
                            <i class="fa-solid ${isComp ? 'fa-file-circle-xmark text-danger' : 'fa-file-shield text-success'} me-1"></i>
                            <code class="text-light small">${escapeHtml(c.filename)}</code>
                        </div>
                        <span class="badge ${isComp ? 'bg-danger animate-pulse' : 'bg-success'} py-1 px-2" style="font-size:0.7rem;">${c.status}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    // 4.5. Update Risk Index Real-Time Calculation Engine & Live Formula Breakdown
    const breakdown = risk.breakdown || {};
    const factors = breakdown.factors || [];

    factors.forEach(f => {
        const valEl = document.getElementById(`rf-${f.key}-val`);
        const ptsEl = document.getElementById(`rf-${f.key}-pts`);
        if (valEl) {
            valEl.innerText = f.live_val;
            valEl.className = f.active ? 'text-danger fw-bold' : 'text-success fw-bold';
        }
        if (ptsEl) {
            ptsEl.innerText = `+${f.points.toFixed(1)} / ${f.max_points}`;
            ptsEl.className = `badge ${f.active ? 'bg-danger animate-pulse' : 'bg-secondary'}`;
        }
    });

    const sumEl = document.getElementById('rf-weighted-sum');
    if (sumEl) sumEl.innerText = (breakdown.weighted_sum || 0.0).toFixed(1);

    // 5. Update 6 Telemetry Submodule Cards
    document.getElementById('telemetry-t2-count').innerText = processes.length;
    document.getElementById('telemetry-t3-entropy').innerText = currEntropy.toFixed(2);
    
    const credCount = events.filter(e => e.code === 'T4').length;
    document.getElementById('telemetry-t4-creds').innerText = credCount;

    const netCount = events.filter(e => e.code === 'T5').length;
    document.getElementById('telemetry-t5-beacons').innerText = netCount;

    const evasionCount = events.filter(e => e.code === 'T6').length;
    document.getElementById('telemetry-t6-inhibition').innerText = evasionCount;

    document.getElementById('telemetry-t7-breaches').innerText = breachedCanaries.length;

    // 6. Update Flagged Processes Table (EXCLUDES TERMINATED PROCESSES)
    document.getElementById('proc-table-count').innerText = `${processes.length} Active`;
    const procBody = document.getElementById('process-table-body');
    if (processes.length === 0) {
        procBody.innerHTML = '<tr><td colspan="5" class="text-secondary text-center py-3">No suspicious processes currently active.</td></tr>';
    } else {
        procBody.innerHTML = processes.slice(0, 8).map(p => {
            const scoreColor = p.threat_score >= 0.75 ? 'danger' : (p.threat_score >= 0.5 ? 'warning' : 'info');
            return `
                <tr id="proc-row-${p.pid}" class="hover-row" onclick="openProcessDetailModal(${p.pid})" title="Click to view detailed process forensics">
                    <td><code>${p.pid}</code></td>
                    <td><strong class="text-light">${escapeHtml(p.name)}</strong></td>
                    <td><span class="badge bg-${scoreColor}">${p.threat_score.toFixed(2)}</span></td>
                    <td class="text-truncate" style="max-width: 180px;" title="${escapeHtml(p.cmdline)}">
                        <code class="text-info">${escapeHtml(p.cmdline)}</code>
                    </td>
                    <td>
                        <button class="btn btn-outline-danger btn-sm py-0 px-2" onclick="event.stopPropagation(); killPid(${p.pid}, '${escapeHtml(p.name)}')">
                            <i class="fa-solid fa-skull me-1"></i> Kill
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // 7. Update Canary Vault Table (Clickable for asset details)
    const canaryBody = document.getElementById('canary-table-body');
    if (canaryBody && canaries.length > 0) {
        canaryBody.innerHTML = canaries.map(c => {
            const isComp = c.status === "COMPROMISED";
            const hashPrefix = (c.expected_hash || '').substring(0, 10);
            return `
                <tr class="hover-row ${isComp ? 'table-danger' : ''}" onclick="openCanaryDetailModal('${escapeHtml(c.filename)}')" title="Click to view detailed asset profile">
                    <td>
                        <i class="fa-solid ${isComp ? 'fa-file-circle-xmark text-danger' : 'fa-file-shield text-success'} me-1"></i>
                        <code class="text-light">${escapeHtml(c.filename)}</code>
                    </td>
                    <td>
                        <span class="badge ${isComp ? 'bg-danger' : 'bg-success'}">${c.status}</span>
                    </td>
                    <td><small><code class="text-info">${hashPrefix}...</code></small></td>
                    <td class="text-truncate" style="max-width: 160px;">
                        <small class="text-light">${escapeHtml(c.breach_details || 'Integrity verified intact')}</small>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // 8. Update Containment Feed
    const containFeed = document.getElementById('containment-action-feed');
    if (containment.length > 0) {
        containFeed.innerHTML = containment.slice(-4).reverse().map(act => `
            <div class="text-truncate py-1 border-bottom border-secondary">
                <span class="text-info">[${act.timestamp.split('T')[1].replace('Z','')}]</span> 
                <strong class="text-warning">${act.action}</strong>: <span class="text-light">${escapeHtml(act.message)}</span>
            </div>
        `).join('');
    }

    // 9. Update Live Event Stream (CLICKABLE TO OPEN EVENT DETAIL WINDOW)
    const eventBody = document.getElementById('event-stream-body');
    if (events.length === 0) {
        eventBody.innerHTML = '<tr><td colspan="4" class="text-secondary text-center py-3">Awaiting telemetry events...</td></tr>';
    } else {
        eventBody.innerHTML = events.slice(0, 15).map((ev, idx) => {
            const sevColor = ev.severity === "CRITICAL" ? "danger" : 
                             (ev.severity === "HIGH" ? "warning" : 
                             (ev.severity === "WARNING" ? "info" : "secondary"));
            const timeStr = ev.timestamp ? ev.timestamp.split('T')[1].replace('Z','') : '';
            return `
                <tr class="hover-row" onclick="openEventDetailModal(${idx})" title="Click to open event detail window">
                    <td><small class="text-secondary">${timeStr}</small></td>
                    <td><span class="badge bg-dark border border-secondary text-info">${ev.code}</span></td>
                    <td><span class="badge bg-${sevColor}">${ev.severity}</span></td>
                    <td class="text-truncate" style="max-width: 320px;" title="${escapeHtml(ev.message)}">
                        <span class="text-light">${escapeHtml(ev.message)}</span>
                    </td>
                </tr>
            `;
        }).join('');
    }
}

// ==================== Simulation Controllers (User-Friendly & Auto-Scroll) ====================

async function runSim(type) {
    const banner = document.getElementById('sim-live-banner');
    const bannerText = document.getElementById('sim-banner-text');
    const bannerIcon = document.getElementById('sim-banner-icon');
    const stepBadge = document.getElementById('sim-step-badge');
    const simBadge = document.getElementById('sim-status-badge');

    const simTitles = {
        'wannacry': 'WannaCry 2.0 (EternalBlue MS17-010 & .wncry)',
        'lockbit3': 'LockBit 3.0 (LockBit Black ChaCha20 Anti-EDR)',
        'blackcat': 'BlackCat / ALPHV (Rust Token Escalation)',
        'ryuk': 'Ryuk Enterprise (PsExec & Backup Service Killer)',
        'conti': 'Conti (32-Thread Concurrent IOCP Engine)',
        'revil': 'REvil / Sodinokibi (Safe-Mode Boot Persistence)',
        'darkside': 'DarkSide Corporate (AD LDAP & Double Extortion)',
        'akira': 'Akira (ESXi & Hypervisor Intermittent Cipher)',
        'royal': 'Royal Ransomware (Partial Byte Evasion)',
        'maze': 'Maze Syndicate (Double Extortion C2 Exfil)',
        'clop': 'Clop CL0P (Event Log Clear & Zero-Day Burst)',
        'hive': 'Hive Ransomware (Golang In-Memory Keystream)',
        'benign': 'Benign Workload Baseline (Low Entropy Control)',
        'full-attack': 'Real-World Ransomware Attack (Full Kill Chain)'
    };

    const title = simTitles[type] || type;

    // 1. Instant User Feedback in the simulation card
    bannerIcon.className = 'fa-solid fa-spinner fa-spin text-warning fs-5 me-2';
    bannerText.innerHTML = `<strong>Running:</strong> ${title} &mdash; <em>Watch top meters react live!</em>`;
    stepBadge.className = 'badge bg-warning text-dark';
    stepBadge.innerText = 'EXECUTING';
    simBadge.className = 'badge bg-warning animate-pulse';
    simBadge.innerText = 'SIMULATION RUNNING';

    // 2. Floating toast alert
    showToast(`🚀 [SIMULATION INITIATED] ${title}! Scrolling to top to observe telemetry response...`, 'warning');

    // 3. Smooth scroll to the top of the command center
    window.scrollTo({ top: 0, behavior: 'smooth' });

    try {
        const resp = await fetch(`/api/simulate/${type}`, { method: 'POST' });
        const res = await resp.json();
        fetchTelemetry(); // Immediate instant poll

        setTimeout(() => {
            bannerIcon.className = 'fa-solid fa-circle-check text-success fs-5 me-2';
            bannerText.innerHTML = `<strong>Completed:</strong> ${title} &mdash; <span class="text-light">${escapeHtml(res.message || 'Dispatched')}</span>`;
            stepBadge.className = 'badge bg-success';
            stepBadge.innerText = 'FINISHED';
            simBadge.className = 'badge bg-info';
            simBadge.innerText = 'READY TO TEST';
            fetchTelemetry();
            fetchReports();
            if (res.prompt_user_for_email || res.ask_email_dispatch) {
                promptSimulationEmail({
                    incident_id: res.incident_id || res.incident_report_id,
                    scenario: res.scenario || res.name || summaryTitle,
                    recipient: res.email_recipient || (res.email_to && res.email_to[0]) || 'ankitnim227@gmail.com',
                    pdf_name: res.pdf_filename || `${res.incident_id}.pdf`
                });
            } else if (res.email_dispatched) {
                const recip = (res.email_to && res.email_to.length > 0) ? res.email_to.join(', ') : 'SOC Admin';
                showToast(`📧 [SOC EMAIL DISPATCHED] Alert PDF report sent to ${recip}!`, 'success');
            }
        }, 800);

    } catch (e) {
        bannerIcon.className = 'fa-solid fa-triangle-exclamation text-danger fs-5 me-2';
        bannerText.innerText = "Error executing simulation: " + e;
        stepBadge.className = 'badge bg-danger';
        stepBadge.innerText = 'ERROR';
    }
}

// ==================== Simulation Email Confirmation Prompt Handlers ====================

let pendingSimulationEmailData = null;

function promptSimulationEmail(data) {
    pendingSimulationEmailData = data;
    ensureModal("simulationEmailPromptModal");
    
    const scEl = document.getElementById('simPromptScenarioName');
    const incEl = document.getElementById('simPromptIncidentId');
    const recipEl = document.getElementById('simPromptRecipient');
    const pdfEl = document.getElementById('simPromptPdfName');
    
    if (scEl) scEl.innerText = data.scenario || 'Test Ransomware Attack Simulation';
    if (incEl) incEl.innerText = data.incident_id || 'SIM-INC-SAMPLE';
    if (recipEl) recipEl.innerText = data.recipient || 'ankitnim227@gmail.com';
    if (pdfEl) pdfEl.innerText = data.pdf_name || `${data.incident_id}.pdf`;
    
    showModalById('simulationEmailPromptModal');
}

function skipSimulationEmail() {
    hideModalById('simulationEmailPromptModal');
    showToast("ℹ️ Test email skipped. Incident report preserved in local EDR archive.", "info");
    pendingSimulationEmailData = null;
}

async function confirmDispatchSimulationEmail() {
    if (!pendingSimulationEmailData) return;
    const btn = document.getElementById('btnConfirmSendSimEmail');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Sending...';
    }
    
    try {
        const resp = await fetch('/api/notify/test-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                incident_id: pendingSimulationEmailData.incident_id,
                scenario: pendingSimulationEmailData.scenario,
                mode: 'test',
                recipients: pendingSimulationEmailData.recipient
            })
        });
        const res = await resp.json();
        hideModalById('simulationEmailPromptModal');
        
        if (resp.ok && (res.status === 'SUCCESS' || res.delivery_status === 'DELIVERED_VIA_SMTP')) {
            showToast(`📧 [TEST EMAIL DISPATCHED] Forensic report for ${pendingSimulationEmailData.incident_id} sent to ${pendingSimulationEmailData.recipient}!`, 'success');
            loadDispatchedEmailsLog();
        } else {
            showToast(`[TEST EMAIL GENERATED] ${res.delivery_details || 'Saved to outbox'}`, 'info');
            loadDispatchedEmailsLog();
        }
    } catch (e) {
        alert("Error dispatching test email: " + e);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-paper-plane me-1"></i> Send Test Email Now';
        }
        pendingSimulationEmailData = null;
    }
}

function triggerFullAttackSim() {
    runSim('full-attack');
}

// ==================== Process Kill & Removal ====================

async function killPid(pid, name) {
    if (!confirm(`Confirm immediate process termination (SIGKILL) on PID ${pid} (${name})?`)) return;
    try {
        const resp = await fetch('/api/control/containment/terminate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid, process_name: name, reason: "Manual SOC Termination" })
        });
        const res = await resp.json();

        // Immediately remove row from the table visually
        const row = document.getElementById(`proc-row-${pid}`);
        if (row) {
            row.remove();
        }

        showToast(`Process ${name} (PID ${pid}) terminated via SIGKILL and removed from active list!`, 'success');
        fetchTelemetry();
    } catch (e) {
        alert("Error terminating process: " + e);
    }
}

function manualKillPid() {
    const input = document.getElementById('manualPidInput');
    const pid = parseInt(input.value);
    if (!pid) {
        alert("Please enter a valid PID.");
        return;
    }
    killPid(pid, "manual_target");
    input.value = '';
}

// ==================== Interactive Modal Inspectors ====================

// ==================== Interactive Modal Inspectors & Helpers ====================

function showModalById(modalId) {
    const el = ensureModal(modalId);
    if (!el) return;
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        try {
            const m = bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el);
            m.show();
            return;
        } catch (e) {
            console.warn("Bootstrap modal failed, using CSS fallback", e);
        }
    }
    // Direct CSS Fallback
    el.style.display = 'block';
    el.classList.add('show');
    el.setAttribute('aria-modal', 'true');
    el.removeAttribute('aria-hidden');
    let backdrop = document.getElementById('modal-fallback-backdrop');
    if (!backdrop) {
        backdrop = document.createElement('div');
        backdrop.id = 'modal-fallback-backdrop';
        backdrop.className = 'modal-backdrop fade show';
        document.body.appendChild(backdrop);
    }
}

function hideModalById(modalId) {
    const el = document.getElementById(modalId);
    if (!el) return;
    if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        try {
            const m = bootstrap.Modal.getInstance(el);
            if (m) m.hide();
        } catch (e) {}
    }
    el.style.display = 'none';
    el.classList.remove('show');
    el.setAttribute('aria-hidden', 'true');
    el.removeAttribute('aria-modal');
    const backdrop = document.getElementById('modal-fallback-backdrop');
    if (backdrop) backdrop.remove();
}

function openRiskFormulaModal() {
    ensureModal("riskFormulaModal");
    showModalById('riskFormulaModal');
}

function scrollToSimulationSuite() {
    const el = document.getElementById('attackScenarioSelect') || document.getElementById('btnRunSelectedScenario');
    if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        try { el.focus(); } catch (e) {}
    }
}

function openEventDetailModal(idx) {
    ensureModal("eventDetailModal");
    if (idx < 0 || idx >= currentTelemetryEvents.length) return;
    const ev = currentTelemetryEvents[idx];

    document.getElementById('modalEventCode').innerText = ev.code || 'T2';
    document.getElementById('modalEventModule').innerText = ev.module || 'Telemetry';
    
    const sevBadge = document.getElementById('modalEventSeverity');
    sevBadge.innerText = ev.severity || 'INFO';
    sevBadge.className = `badge fs-6 bg-${ev.severity === 'CRITICAL' ? 'danger' : (ev.severity === 'HIGH' ? 'warning text-dark' : 'info')}`;

    document.getElementById('modalEventTimestamp').innerText = ev.timestamp || 'N/A';
    document.getElementById('modalEventMessage').innerText = ev.message || '';
    document.getElementById('modalEventJson').innerText = JSON.stringify(ev, null, 2);

    showModalById('eventDetailModal');
}

async function openCanaryDetailModal(filename) {
    ensureModal("canaryDetailModal");
    let canary = currentCanaries.find(c => c.filename === filename);
    if (!canary || !canary.attacker_process) {
        try {
            const resp = await fetch(`/api/canaries/${encodeURIComponent(filename)}`);
            if (resp.ok) {
                const fetched = await resp.json();
                canary = fetched.canary || fetched;
            }
        } catch (e) {
            console.error("Failed to fetch canary details:", e);
        }
    }
    if (!canary) return;

    document.getElementById('canaryModalFilename').innerText = canary.filename;
    document.getElementById('canaryModalDesc').innerText = canary.description || 'Deception Decoy File';
    
    const statusBadge = document.getElementById('canaryModalStatus');
    statusBadge.innerText = canary.status;
    statusBadge.className = `badge fs-6 px-3 py-2 ${canary.status === 'COMPROMISED' ? 'bg-danger animate-pulse' : 'bg-success'}`;

    // Attacker Attribution Box (Who triggered it, when it happened, malware family, tamper type)
    const attackerBox = document.getElementById('canaryModalAttackerBox');
    if (attackerBox) {
        if (canary.status === 'COMPROMISED') {
            attackerBox.classList.remove('d-none');
            const famEl = document.getElementById('canaryModalThreatFamily');
            if (famEl) famEl.innerText = canary.attacker_family || 'Active Adversary Ransomware';
            const procEl = document.getElementById('canaryModalAttackerProc');
            if (procEl) procEl.innerText = canary.attacker_process || 'ransomware_payload.exe';
            const pidEl = document.getElementById('canaryModalAttackerPid');
            if (pidEl) pidEl.innerText = canary.attacker_pid || 'Unknown PID';
            const compEl = document.getElementById('canaryModalCompromisedAt');
            if (compEl) compEl.innerText = canary.compromised_at || 'Recorded in telemetry stream';
            const typeEl = document.getElementById('canaryModalTamperType');
            if (typeEl) typeEl.innerText = canary.tamper_type || 'In-place Ransomware Encryption / Overwrite';
        } else {
            attackerBox.classList.add('d-none');
        }
    }

    document.getElementById('canaryModalPath').innerText = canary.path || `/canary_vault/${canary.filename}`;
    document.getElementById('canaryModalExpectedHash').innerText = canary.expected_hash || 'Uncalculated';
    document.getElementById('canaryModalCurrentHash').innerText = canary.current_hash || canary.expected_hash || 'Uncalculated';
    document.getElementById('canaryModalBreach').innerHTML = canary.status === 'COMPROMISED' ? 
        `<strong class="text-danger">${escapeHtml(canary.breach_details || 'Unauthorized modification or deletion detected!')}</strong>` :
        `<span class="text-success"><i class="fa-solid fa-check me-1"></i> Integrity verified. File is intact.</span>`;

    showModalById('canaryDetailModal');
}

async function openProcessDetailModal(pid) {
    ensureModal("processDetailModal");
    let proc = currentProcesses.find(p => p.pid === pid);
    if (!proc) {
        try {
            const resp = await fetch(`/api/processes/${pid}`);
            if (resp.ok) {
                const data = await resp.json();
                proc = data.process;
            }
        } catch (e) {
            console.error("Failed to fetch process details:", e);
        }
    }
    if (!proc) return;

    currentModalProcPid = proc.pid;
    currentModalProcName = proc.name || 'malware_binary';

    document.getElementById('procModalName').innerText = proc.name || 'unknown_process';
    document.getElementById('procModalPid').innerText = proc.pid;
    document.getElementById('procModalPpid').innerText = proc.ppid || 'N/A';
    document.getElementById('procModalParent').innerText = proc.parent_name || 'cmd_runner';

    const statusBadge = document.getElementById('procModalStatus');
    const isQuar = proc.status === 'QUARANTINED' || (proc.status && proc.status.includes('TERMINATED'));
    statusBadge.innerText = isQuar ? 'NEUTRALIZED / QUARANTINED' : 'SUSPICIOUS (ACTIVE)';
    statusBadge.className = `badge fs-6 px-3 py-2 ${isQuar ? 'bg-secondary' : 'bg-danger animate-pulse'}`;

    document.getElementById('procModalExe').innerText = proc.exe || `/tmp/${proc.name}`;
    document.getElementById('procModalCmdline').innerText = proc.cmdline || proc.name;

    const score = proc.threat_score || 0.0;
    const scoreBadge = document.getElementById('procModalThreatScore');
    scoreBadge.innerText = `${score.toFixed(2)} / 1.00 (${score >= 0.75 ? 'CRITICAL RISK' : 'ELEVATED RISK'})`;
    scoreBadge.className = `badge fs-6 ${score >= 0.75 ? 'bg-danger' : 'bg-warning text-dark'}`;

    document.getElementById('procModalCpu').innerText = `${proc.cpu_percent || 12.5}%`;
    document.getElementById('procModalMem').innerText = `${proc.memory_mb || 42.0} MB`;

    const flagsContainer = document.getElementById('procModalFlags');
    const flags = proc.flags || ["Suspicious process execution pattern"];
    flagsContainer.innerHTML = flags.map(f => `<span class="badge bg-danger-subtle text-danger border border-danger me-1 mb-1">${escapeHtml(f)}</span>`).join('');

    document.getElementById('procModalUser').innerText = proc.user || 'root';

    const killBtn = document.getElementById('procModalKillBtn');
    if (killBtn) {
        killBtn.style.display = isQuar ? 'none' : 'inline-block';
    }

    showModalById('processDetailModal');
}

async function killModalProcess() {
    if (currentModalProcPid) {
        hideModalById('processDetailModal');
        await killPid(currentModalProcPid, currentModalProcName);
    }
}

// ==================== Toast Notifications ====================

function showToast(message, type = 'info') {
    const toastEl = document.getElementById('socNotificationToast');
    const msgEl = document.getElementById('toastMessage');
    const iconEl = document.getElementById('toastIcon');

    msgEl.innerText = message;
    if (type === 'warning') {
        iconEl.className = 'fa-solid fa-triangle-exclamation text-warning fs-5 me-2';
        toastEl.className = 'toast align-items-center text-bg-dark border border-warning soc-toast show';
    } else if (type === 'success') {
        iconEl.className = 'fa-solid fa-circle-check text-success fs-5 me-2';
        toastEl.className = 'toast align-items-center text-bg-dark border border-success soc-toast show';
    } else {
        iconEl.className = 'fa-solid fa-info-circle text-info fs-5 me-2';
        toastEl.className = 'toast align-items-center text-bg-dark border border-info soc-toast show';
    }
    toastEl.classList.remove('d-none');
    setTimeout(hideToast, 4000);
}

function hideToast() {
    const toastEl = document.getElementById('socNotificationToast');
    if (toastEl) toastEl.classList.add('d-none');
}

// ==================== Network Containment & Actions ====================

async function isolateNetwork() {
    if (!confirm("Isolate endpoint from local network and internet?")) return;
    try {
        const resp = await fetch('/api/control/containment/isolate-network', { method: 'POST' });
        const res = await resp.json();
        showToast("Endpoint Network Isolated via Firewall Quarantine!", 'warning');
        fetchTelemetry();
    } catch (e) {
        alert("Network isolation error: " + e);
    }
}

async function restoreNetwork() {
    try {
        const resp = await fetch('/api/control/containment/restore-network', { method: 'POST' });
        const res = await resp.json();
        showToast("Endpoint Network Connectivity Restored.", 'success');
        fetchTelemetry();
    } catch (e) {
        alert("Error restoring network: " + e);
    }
}

async function resetCanaries() {
    try {
        const resp = await fetch('/api/control/canary/reset', { method: 'POST' });
        const res = await resp.json();
        showToast("Canary Decoys restored and Tripwires re-armed!", 'success');
        fetchTelemetry();
    } catch (e) {
        alert("Error resetting canaries: " + e);
    }
}

async function resumeAllServicesNormal() {
    try {
        const resp = await fetch('/api/control/system/resume-normal', { method: 'POST' });
        const res = await resp.json();
        if (resp.ok && res.status === "SUCCESS") {
            showToast("All services successfully resumed! Network reconnected and pre-attack baseline restored.", "success");
            await fetchTelemetry();
            await fetchReports();
        } else {
            showToast("Failed to resume services: " + (res.message || "Unknown error"), "danger");
        }
    } catch (e) {
        showToast("Error resuming services: " + e.message, "danger");
    }
}

async function toggleAutoResponse(enabled) {
    try {
        await fetch('/api/control/auto-response/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        const badge = document.getElementById('auto-response-badge');
        if (enabled) {
            badge.className = 'badge bg-success-subtle text-success border border-success me-3 px-3 py-2';
            badge.innerHTML = '<i class="fa-solid fa-robot me-1"></i> Auto-Containment: <strong>ACTIVE</strong>';
            showToast("Automated Containment Engine Armed", 'success');
        } else {
            badge.className = 'badge bg-warning-subtle text-warning border border-warning me-3 px-3 py-2';
            badge.innerHTML = '<i class="fa-solid fa-robot me-1"></i> Auto-Containment: <strong>DISABLED</strong>';
            showToast("Automated Containment Disabled", 'warning');
        }
    } catch (e) {
        console.error(e);
    }
}

// ==================== SOC Admin Alert & Recipient Configuration ====================

let currentNotifyConfig = {
    soc_email: "ankitnim227@gmail.com",
    secondary_emails: ["soc-tier3@enterprise.org", "ciso-direct@enterprise.org"],
    admin_name: "Chief Information Security Officer",
    webhook_url: "http://127.0.0.1:8000/api/webhook/alerts",
    broadcast_channel: "#critical-secops-war-room",
    phone_sms: "+1-888-999-SECOPS",
    alert_cooldown_sec: 5,
    smtp: {
        enabled: false,
        host: "smtp.gmail.com",
        port: 587,
        use_tls: true,
        username: "ankitnim227@gmail.com",
        password: ""
    }
};

async function openNotifyAdminModal() {
    ensureModal("notifyAdminModal");
    try {
        const resp = await fetch('/api/notify/config');
        if (resp.ok) {
            currentNotifyConfig = await resp.json();
        }
    } catch (e) {
        console.warn("Could not load /api/notify/config:", e);
    }

    // Populate modal inputs
    const pEmail = document.getElementById('notifPrimaryEmail');
    if (pEmail) pEmail.value = currentNotifyConfig.soc_email || "ankitnim227@gmail.com";

    const aName = document.getElementById('notifAdminName');
    if (aName) aName.value = currentNotifyConfig.admin_name || "Chief Information Security Officer";

    const sEmails = document.getElementById('notifSecondaryEmails');
    if (sEmails) {
        const secList = currentNotifyConfig.secondary_emails || [];
        sEmails.value = Array.isArray(secList) ? secList.join(', ') : secList;
    }

    const bChan = document.getElementById('notifBroadcastChannel');
    if (bChan) bChan.value = currentNotifyConfig.broadcast_channel || "#critical-secops-war-room";

    const phone = document.getElementById('notifPhone');
    if (phone) phone.value = currentNotifyConfig.phone_sms || "+1-888-999-SECOPS";

    const webhook = document.getElementById('notifWebhookUrl');
    if (webhook) webhook.value = currentNotifyConfig.webhook_url || "http://127.0.0.1:8000/api/webhook/alerts";

    // Populate SMTP inputs
    const smtp = currentNotifyConfig.smtp || {};
    const smtpEnabled = document.getElementById('notifSmtpEnabled');
    if (smtpEnabled) smtpEnabled.checked = Boolean(smtp.enabled);

    const smtpHost = document.getElementById('notifSmtpHost');
    if (smtpHost) smtpHost.value = smtp.host || "smtp.gmail.com";

    const smtpPort = document.getElementById('notifSmtpPort');
    if (smtpPort) smtpPort.value = smtp.port || 587;

    const smtpTls = document.getElementById('notifSmtpTls');
    if (smtpTls) smtpTls.checked = smtp.use_tls !== false;

    const smtpUser = document.getElementById('notifSmtpUser');
    if (smtpUser) smtpUser.value = smtp.username || currentNotifyConfig.soc_email || "ankitnim227@gmail.com";

    const smtpPwd = document.getElementById('notifSmtpPassword');
    if (smtpPwd && smtp.has_password && !smtpPwd.value) {
        smtpPwd.placeholder = "•••••••• (Password saved)";
    }

    const statusBadge = document.getElementById('notifConfigStatusBadge');
    if (statusBadge) {
        statusBadge.className = 'badge bg-success';
        statusBadge.innerText = 'Synchronized';
    }

    // Load recent dispatched emails outbox log
    loadDispatchedEmailsLog();

    // Show modal
    const modalEl = document.getElementById('notifyAdminModal');
    if (modalEl) {
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
    }
}

function promptNotifyAdmin() {
    openNotifyAdminModal();
}

async function loadNotificationHistory() {
    const container = document.getElementById('notifHistoryContainer');
    if (!container) return;

    try {
        const resp = await fetch('/api/telemetry');
        if (resp.ok) {
            const data = await resp.json();
            const notifs = data.notifications || [];
            if (notifs.length === 0) {
                container.innerHTML = '<span class="text-secondary fst-italic">No prior alert dispatches recorded in current session.</span>';
                return;
            }

            container.innerHTML = notifs.slice().reverse().map(n => {
                const recips = Array.isArray(n.recipients) ? n.recipients.join(', ') : (n.recipients || 'SOC Admin');
                const sevBadge = n.severity === 'CRITICAL' ? 'bg-danger' : (n.severity === 'HIGH' ? 'bg-warning text-dark' : 'bg-info');
                return `<div class="d-flex justify-content-between align-items-center py-1 border-bottom border-dark">
                    <div>
                        <span class="badge ${sevBadge} me-1">${escapeHtml(n.severity || 'ALERT')}</span>
                        <strong class="text-light">${escapeHtml(n.title || 'Notification')}</strong>
                        <div class="text-secondary" style="font-size: 0.72rem;">
                            <i class="fa-solid fa-paper-plane me-1"></i>To: <span class="text-info">${escapeHtml(recips)}</span> 
                            &bull; Channel: <code>${escapeHtml(n.channel || 'Default')}</code> 
                            &bull; Admin: ${escapeHtml(n.admin_contact || 'On-Call')}
                        </div>
                    </div>
                    <small class="text-secondary text-nowrap ms-2">${escapeHtml(n.timestamp || '')}</small>
                </div>`;
            }).join('');
        }
    } catch (e) {
        container.innerHTML = '<span class="text-secondary">Unable to load dispatch log.</span>';
    }
}

async function saveNotifyConfig(closeModal = false) {
    const pEmail = document.getElementById('notifPrimaryEmail')?.value.trim();
    const aName = document.getElementById('notifAdminName')?.value.trim();
    const sEmailsRaw = document.getElementById('notifSecondaryEmails')?.value.trim();
    const bChan = document.getElementById('notifBroadcastChannel')?.value.trim();
    const phone = document.getElementById('notifPhone')?.value.trim();
    const webhook = document.getElementById('notifWebhookUrl')?.value.trim();

    const secArray = sEmailsRaw ? sEmailsRaw.split(',').map(s => s.trim()).filter(s => s.length > 0) : [];

    // SMTP fields
    const smtpEnabled = document.getElementById('notifSmtpEnabled')?.checked || false;
    const smtpHost = document.getElementById('notifSmtpHost')?.value.trim() || 'smtp.gmail.com';
    const smtpPort = parseInt(document.getElementById('notifSmtpPort')?.value) || 587;
    const smtpTls = document.getElementById('notifSmtpTls')?.checked !== false;
    const smtpUser = document.getElementById('notifSmtpUser')?.value.trim() || pEmail || 'ankitnim227@gmail.com';
    const smtpPwd = document.getElementById('notifSmtpPassword')?.value.trim() || '';

    const payload = {
        soc_email: pEmail || "ankitnim227@gmail.com",
        secondary_emails: secArray,
        admin_name: aName || "Chief Information Security Officer",
        broadcast_channel: bChan || "#critical-secops-war-room",
        phone_sms: phone || "+1-888-999-SECOPS",
        webhook_url: webhook || "http://127.0.0.1:8000/api/webhook/alerts",
        smtp: {
            enabled: smtpEnabled,
            host: smtpHost,
            port: smtpPort,
            use_tls: smtpTls,
            username: smtpUser,
            from_email: smtpUser,
            from_name: "RansomGuard EDR SOC Alerting"
        }
    };
    if (smtpPwd) {
        payload.smtp.password = smtpPwd;
    }

    try {
        const resp = await fetch('/api/notify/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            const res = await resp.json();
            currentNotifyConfig = res.config || payload;
            const statusBadge = document.getElementById('notifConfigStatusBadge');
            if (statusBadge) {
                statusBadge.className = 'badge bg-success';
                statusBadge.innerText = 'Saved ✓';
            }
            showToast(`✅ Alert recipient & SMTP configuration updated! Primary: ${payload.soc_email}`, 'success');

            if (closeModal) {
                const modalEl = document.getElementById('notifyAdminModal');
                if (modalEl) {
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    if (modal) modal.hide();
                }
            }
        } else {
            showToast("Failed to save recipient configuration.", 'danger');
        }
    } catch (e) {
        showToast("Error updating recipient config: " + e, 'danger');
    }
}

async function testEmailDelivery(mode = 'test') {
    const isReal = (mode === 'real');
    const btn = document.getElementById(isReal ? 'realAlertBtn' : 'testEmailBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Dispatching...';
    }

    // Auto-save any modified fields first
    await saveNotifyConfig(false);

    const pEmail = document.getElementById('notifPrimaryEmail')?.value.trim() || 'ankitnim227@gmail.com';
    try {
        const resp = await fetch('/api/notify/test-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ soc_email: pEmail, mode: mode })
        });
        const res = await resp.json();
        const modeLabel = isReal ? 'LIVE INCIDENT ALERT' : 'TEST RANSOMWARE ATTACK';
        if (res.delivery_status === 'DELIVERED_VIA_SMTP') {
            showToast(`✅ [${modeLabel} SENT VIA SMTP] Alert & forensic report delivered to ${pEmail}!`, 'success');
        } else {
            showToast(`ℹ️ [${modeLabel} COMPILED] ${res.delivery_details}`, 'info');
        }
        // Immediately refresh the outbox feed
        loadDispatchedEmailsLog();
        fetchReports();
    } catch (e) {
        showToast("Error testing email delivery: " + e, 'danger');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = isReal ?
                '<i class="fa-solid fa-radiation me-1"></i>Send Sample Live Alert Email' :
                '<i class="fa-solid fa-flask-vial me-1"></i>Send Test Email (Simulation)';
        }
    }
}

async function loadDispatchedEmailsLog() {
    const container = document.getElementById('notifEmailsContainer');
    if (!container) return;

    try {
        const resp = await fetch('/api/notifications/emails?limit=12');
        if (!resp.ok) {
            container.innerHTML = '<span class="text-secondary small">Unable to retrieve email log.</span>';
            return;
        }
        const data = await resp.json();
        const emails = data.emails || [];
        if (emails.length === 0) {
            container.innerHTML = '<div class="text-secondary small text-center py-2">No email alerts recorded yet. Click one of the test buttons above or detonate a simulation.</div>';
            return;
        }

        container.innerHTML = emails.map(e => {
            const isSim = e.is_simulation;
            const badgeType = isSim ?
                '<span class="badge" style="background:#7c3aed; color:#fff; font-size:10px;"><i class="fa-solid fa-flask-vial me-1"></i>TEST ATTACK</span>' :
                '<span class="badge bg-danger animate-pulse" style="font-size:10px;"><i class="fa-solid fa-radiation me-1"></i>LIVE ALERT</span>';
            const delivStatus = e.delivery_status || 'SENT';
            const isDeliveredSmtp = delivStatus.includes('SMTP') && !delivStatus.includes('OFFLINE') && !delivStatus.includes('FAILED');
            const delivBadge = isDeliveredSmtp ?
                '<span class="badge bg-success" style="font-size:10px;"><i class="fa-solid fa-check-double me-1"></i>Delivered (SMTP)</span>' :
                `<span class="badge bg-info text-dark" style="font-size:10px;" title="${escapeHtml(e.delivery_details || '')}"><i class="fa-solid fa-hard-drive me-1"></i>Spooled Outbox</span>`;
            const pdfBadge = e.has_pdf_attachment ?
                `<span class="badge bg-dark border border-secondary text-danger" style="font-size:10px;"><i class="fa-solid fa-file-pdf me-1"></i>PDF Attached</span>` : '';
            const toStr = Array.isArray(e.to) ? e.to.join(', ') : (e.to || 'SOC Admin');

            return `<div class="p-2 mb-2 rounded bg-black border border-secondary">
                <div class="d-flex justify-content-between align-items-center mb-1 flex-wrap gap-1">
                    <div>
                        ${badgeType}
                        ${delivBadge}
                        ${pdfBadge}
                        <strong class="text-light ms-1 small">${escapeHtml(e.subject || 'Incident Notification')}</strong>
                    </div>
                    <small class="text-secondary text-nowrap">${escapeHtml(e.timestamp || '')}</small>
                </div>
                <div class="text-secondary small d-flex justify-content-between align-items-center flex-wrap gap-1" style="font-size: 0.73rem;">
                    <span><i class="fa-solid fa-envelope me-1"></i>To: <strong class="text-info">${escapeHtml(toStr)}</strong> &bull; Incident: <code>${escapeHtml(e.incident_id || '')}</code></span>
                    ${e.id ? `<a href="/api/notifications/emails/${escapeHtml(e.id)}/eml" class="btn btn-outline-secondary btn-sm py-0 px-2" style="font-size: 0.7rem;" title="Download raw RFC-822 .eml message"><i class="fa-solid fa-download me-1"></i>.eml</a>` : ''}
                </div>
                <div class="text-light mt-1 fst-italic px-2 py-1 rounded" style="font-size: 0.72rem; background: rgba(255,255,255,0.03); border-left: 2px solid ${isSim ? '#8b5cf6' : '#ef4444'};">
                    ${escapeHtml(e.short_note || '')}
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        container.innerHTML = '<span class="text-secondary small">Error loading email outbox log.</span>';
    }
}

function resetNotifyConfigToDefaults() {
    if (confirm("Reset alert recipient settings to enterprise defaults?")) {
        const pEmail = document.getElementById('notifPrimaryEmail');
        if (pEmail) pEmail.value = "ankitnim227@gmail.com";

        const aName = document.getElementById('notifAdminName');
        if (aName) aName.value = "Chief Information Security Officer";

        const sEmails = document.getElementById('notifSecondaryEmails');
        if (sEmails) sEmails.value = "soc-tier3@enterprise.org, ciso-direct@enterprise.org";

        const bChan = document.getElementById('notifBroadcastChannel');
        if (bChan) bChan.value = "#critical-secops-war-room";

        const phone = document.getElementById('notifPhone');
        if (phone) phone.value = "+1-888-999-SECOPS";

        const webhook = document.getElementById('notifWebhookUrl');
        if (webhook) webhook.value = "http://127.0.0.1:8000/api/webhook/alerts";

        const smtpEnabled = document.getElementById('notifSmtpEnabled');
        if (smtpEnabled) smtpEnabled.checked = false;

        const smtpHost = document.getElementById('notifSmtpHost');
        if (smtpHost) smtpHost.value = "smtp.gmail.com";

        const smtpPort = document.getElementById('notifSmtpPort');
        if (smtpPort) smtpPort.value = 587;

        const smtpTls = document.getElementById('notifSmtpTls');
        if (smtpTls) smtpTls.checked = true;

        const smtpUser = document.getElementById('notifSmtpUser');
        if (smtpUser) smtpUser.value = "ankitnim227@gmail.com";

        const smtpPwd = document.getElementById('notifSmtpPassword');
        if (smtpPwd) smtpPwd.value = "";

        const statusBadge = document.getElementById('notifConfigStatusBadge');
        if (statusBadge) {
            statusBadge.className = 'badge bg-warning text-dark';
            statusBadge.innerText = 'Modified (Click Save)';
        }
    }
}

async function dispatchCustomAlert() {
    const pEmail = document.getElementById('notifPrimaryEmail')?.value.trim() || "soc-alerts@enterprise-defense.local";
    const aName = document.getElementById('notifAdminName')?.value.trim() || "SOC Incident Commander";
    const sEmailsRaw = document.getElementById('notifSecondaryEmails')?.value.trim() || "";
    const bChan = document.getElementById('notifBroadcastChannel')?.value.trim() || "SOC-CRITICAL-SECOPS";
    const phone = document.getElementById('notifPhone')?.value.trim() || "+1-800-555-SECOPS";
    const webhook = document.getElementById('notifWebhookUrl')?.value.trim() || "http://127.0.0.1:8000/api/webhook/alerts";

    const sev = document.getElementById('notifSeveritySelect')?.value || "CRITICAL";
    const title = document.getElementById('notifAlertTitle')?.value.trim() || "URGENT: Ransomware Early Warning & Active Threat Alert";
    const notes = document.getElementById('notifAlertNotes')?.value.trim() || "Manual emergency alert dispatched via SOC Command Center";

    const secArray = sEmailsRaw ? sEmailsRaw.split(',').map(s => s.trim()).filter(s => s.length > 0) : [];
    const allRecipients = [pEmail, ...secArray.filter(e => e !== pEmail)];

    const payload = {
        title: title,
        severity: sev,
        soc_email: pEmail,
        secondary_emails: secArray,
        recipients: allRecipients,
        admin_name: aName,
        broadcast_channel: bChan,
        phone_sms: phone,
        webhook_url: webhook,
        save_as_default: true,
        details: {
            notes: notes,
            manual_trigger: true,
            admin: aName,
            channel: bChan,
            sms_target: phone,
            timestamp_utc: new Date().toISOString()
        }
    };

    try {
        const resp = await fetch('/api/notify/dispatch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            const res = await resp.json();
            const recipsStr = allRecipients.slice(0, 3).join(', ') + (allRecipients.length > 3 ? ` +${allRecipients.length - 3} more` : '');
            showToast(`🚨 [EMERGENCY ALERT DISPATCHED] Alert sent to ${recipsStr} via ${bChan}!`, 'danger');
            
            // Reload history in modal
            loadNotificationHistory();
            fetchTelemetry();

            // Close modal after brief delay
            setTimeout(() => {
                const modalEl = document.getElementById('notifyAdminModal');
                if (modalEl) {
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    if (modal) modal.hide();
                }
            }, 1200);
        } else {
            showToast("Failed to dispatch alert.", 'danger');
        }
    } catch (e) {
        showToast("Error dispatching alert: " + e, 'danger');
    }
}

async function generateIncidentReport() {
    try {
        showToast("Compiling NIST SP 800-61 / MITRE ATT&CK Incident Report...", 'info');
        const resp = await fetch('/api/reports/generate', { method: 'POST' });
        const res = await resp.json();
        currentActiveIncidentId = res.incident_id;
        fetchReports();
        openReportModal(res.incident_id);
    } catch (e) {
        alert("Failed to generate incident report: " + e);
    }
}

async function fetchReports() {
    try {
        const resp = await fetch('/api/reports');
        if (!resp.ok) return;
        const data = await resp.json();
        const reports = data.reports || [];
        const body = document.getElementById('reports-table-body');
        if (reports.length === 0) {
            body.innerHTML = '<tr><td colspan="5" class="text-secondary text-center py-3">No incident reports generated yet. Reports appear automatically upon attack detonation.</td></tr>';
            return;
        }

        body.innerHTML = reports.slice(0, 10).map(r => {
            const isSim = r.is_simulation || (r.incident_id && r.incident_id.startsWith('SIM-'));
            const scenario = r.scenario || (isSim ? 'Simulated Adversary Drill' : 'Live Host Incident');
            const classBadge = isSim ? 
                `<span class="badge px-2 py-1" style="background:#7c3aed; color:#fff; border: 1px solid #c084fc;" title="Controlled security drill"><i class="fa-solid fa-flask-vial me-1"></i> SIMULATED DRILL</span>` :
                `<span class="badge bg-danger px-2 py-1 animate-pulse" style="border: 1px solid #fca5a5;" title="Production host event"><i class="fa-solid fa-radiation me-1"></i> LIVE INCIDENT</span>`;
            return `
            <tr>
                <td>
                    <i class="fa-solid fa-file-contract ${isSim ? 'text-info' : 'text-danger'} me-1"></i>
                    <strong class="text-light">${escapeHtml(r.incident_id)}</strong>
                    <span class="badge bg-dark border border-secondary text-info ms-1" style="font-size:0.68rem;" title="Automated email alert with PDF report dispatched to SOC"><i class="fa-solid fa-paper-plane me-1"></i>Emailed</span>
                </td>
                <td>${classBadge}</td>
                <td><span class="text-light small fw-bold">${escapeHtml(scenario)}</span></td>
                <td><small class="text-secondary">${escapeHtml(r.created_at)}</small></td>
                <td>
                    <button class="btn btn-outline-info btn-sm py-0 px-2 me-1" onclick="openReportModal('${escapeHtml(r.incident_id)}')">
                        <i class="fa-solid fa-eye"></i> View
                    </button>
                    <a href="/api/reports/download-pdf/${escapeHtml(r.incident_id)}" class="btn btn-outline-danger btn-sm py-0 px-2 me-1" title="Download PDF Report">
                        <i class="fa-solid fa-file-pdf"></i> PDF
                    </a>
                    <a href="/api/reports/view/${escapeHtml(r.incident_id)}?format=markdown" target="_blank" class="btn btn-outline-secondary btn-sm py-0 px-2">
                        .md
                    </a>
                </td>
            </tr>
            `;
        }).join('');
    } catch (e) {
        console.error(e);
    }
}

function openReportModal(incId) {
    ensureModal("reportModal");
    const idToUse = incId || currentActiveIncidentId;
    if (!idToUse) {
        generateIncidentReport();
        return;
    }
    const frame = document.getElementById('reportFrame');
    frame.src = `/api/reports/view/${idToUse}`;
    document.getElementById('downloadMdBtn').href = `/api/reports/view/${idToUse}?format=markdown`;
    document.getElementById('downloadPdfBtn').href = `/api/reports/download-pdf/${idToUse}`;

    const modalTitle = document.getElementById('reportModalLabel');
    if (modalTitle) {
        if (idToUse.startsWith('SIM-')) {
            modalTitle.innerHTML = `<span class="badge me-2" style="background:#7c3aed; color:#fff; border: 1px solid #c084fc;"><i class="fa-solid fa-flask-vial me-1"></i> TEST SIMULATION</span> Forensic Incident Report &mdash; <code class="text-info">${escapeHtml(idToUse)}</code> <span class="badge bg-success ms-2"><i class="fa-solid fa-paper-plane me-1"></i> SOC Emailed (PDF Attached)</span>`;
        } else {
            modalTitle.innerHTML = `<span class="badge bg-danger me-2 animate-pulse" style="border: 1px solid #fca5a5;"><i class="fa-solid fa-radiation me-1"></i> PRODUCTION LIVE THREAT</span> Forensic Incident Report &mdash; <code class="text-danger">${escapeHtml(idToUse)}</code> <span class="badge bg-success ms-2"><i class="fa-solid fa-paper-plane me-1"></i> SOC Emailed (PDF Attached)</span>`;
        }
    }

    showModalById('reportModal');
}

function printReportIframe() {
    const frame = document.getElementById('reportFrame');
    if (frame && frame.contentWindow) {
        frame.contentWindow.focus();
        frame.contentWindow.print();
    }
}

// ==================== Scenario Selector & Dynamic Description ====================

const SCENARIO_DESCRIPTIONS = {
    'wannacry': {
        badge: 'MS17-010 ETERNALBLUE LATERAL WORM',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (@WanaDecryptor@), T3 (Entropy .wncry), T5 (Port 445 SMB), T6 (VSS Wipe), T7',
        text: 'Emulates the historic <strong>WannaCry 2.0 (WanaCrypt0r)</strong> kill chain: exploits SMBv1 port 445 to propagate laterally, checks killswitch domain, spawns <code>@WanaDecryptor@.exe</code>, executes shadow copy deletion via <code>vssadmin delete shadows</code>, and executes mass file encryption with <code>.wncry</code>.'
    },
    'lockbit3': {
        badge: 'LOCKBIT 3.0 (LOCKBIT BLACK)',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (lockbit3_encryptor), T3 (ChaCha20 .lockbit), T6 (Anti-EDR VSS), T7 (Canary)',
        text: 'Emulates <strong>LockBit 3.0 Black</strong>: multi-threaded ChaCha20/RSA encryption bursts, unhooking EDR monitoring DLLs, terminating database/backup services, tampering with decoy canaries, and locking filesystem with <code>.lockbit</code>.'
    },
    'blackcat': {
        badge: 'BLACKCAT / ALPHV (RUST ENGINE)',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (alphv_blackcat), T3 (AES-GCM .alphv), T4 (Token Steal), T5 (C2 Exfil), T7',
        text: 'Emulates <strong>BlackCat / ALPHV</strong>: high-performance Rust binary execution, token privilege escalation (SeDebugPrivilege), UAC bypass, HTTPS C2 exfiltration, and cryptographic file renaming with <code>.alphv</code>.'
    },
    'ryuk': {
        badge: 'RYUK ENTERPRISE RANSOMWARE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (ryuk_stealth), T3 (.ryk Encryption), T5 (PsExec SMB), T6 (40+ Service Kills), T7',
        text: 'Emulates <strong>Ryuk Ransomware</strong>: enterprise reconnaissance, PsExec lateral execution, systematic termination of 40+ security and backup services (<code>net stop "Volume Shadow Copy"</code>), and rapid <code>.ryk</code> file encryption.'
    },
    'conti': {
        badge: 'CONTI 32-THREAD IOCP ENGINE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (conti_worker), T3 (32 Threads .conti), T5 (ARP Subnet Sweep), T6 (WMIC Delete), T7',
        text: 'Emulates <strong>Conti Ransomware</strong>: ultra-fast multi-threaded encryption using Windows I/O Completion Ports across 32 concurrent threads, deleting volume shadow copies via WMIC, and writing <code>.conti</code> extensions.'
    },
    'revil': {
        badge: 'REVIL / SODINOKIBI (SAFE-MODE REBOOT)',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (revil_agent), T3 (Salsa20 .revil), T6 (bcdedit), T7 (Canary)',
        text: 'Emulates <strong>REvil / Sodinokibi</strong>: persists through Safe-Mode reboots, uses <code>bcdedit</code> to disable boot error recovery, manipulates kernel registry run keys, and detonates bulk <code>.revil</code> encryption.'
    },
    'darkside': {
        badge: 'DARKSIDE DOUBLE-EXTORTION',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (darkside_crypto), T3 (Salsa20 .darkside), T4 (AD LDAP), T5 (Pre-encryption Exfil), T7',
        text: 'Emulates <strong>DarkSide Corporate Ransomware</strong>: Active Directory LDAP credential harvesting, pre-encryption double-extortion exfiltration beacons, volume shadow copy deletion, and Salsa20 <code>.darkside</code> file locking.'
    },
    'akira': {
        badge: 'AKIRA HYPERVISOR & ESXI THREAT',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (akira_crypt), T3 (Intermittent .akira), T6 (PowerShell Shadow Wipe), T7',
        text: 'Emulates <strong>Akira Ransomware</strong>: targets workstation files and virtual machine disks, deletes shadow copies via PowerShell WMI scripts, and uses intermittent block encryption with <code>.akira</code> extensions.'
    },
    'royal': {
        badge: 'ROYAL PARTIAL BYTE EVASION',
        badgeClass: 'bg-warning text-dark',
        target: 'Vectors: T2 (royal_payload), T3 (Partial Encryption .royal), T6 (VSS Suppress), T7',
        text: 'Emulates <strong>Royal Ransomware</strong>: encrypts alternating partial byte blocks to evade simple sliding-window entropy thresholds, disables SMB packet signing, deletes shadow copies, and writes <code>.royal</code> files.'
    },
    'maze': {
        badge: 'MAZE ORIGINAL DOUBLE EXTORTION',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (maze_encryptor), T3 (ChaCha20 .maze), T5 (Base64 C2 Exfil), T7 (Decoy Seek)',
        text: 'Emulates <strong>Maze Syndicate</strong>: the pioneer of double extortion that seeks out high-value file directories and decoy canary assets, exfiltrates corporate archives to external C2, and locks disks with <code>.maze</code>.'
    },
    'clop': {
        badge: 'CLOP (CL0P) ZERO-DAY INTRUDER',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (clop_ransom), T3 (Batch .clop), T6 (wevtutil Event Log Wipe), T7',
        text: 'Emulates <strong>Clop (CL0P)</strong>: zero-day vulnerability intrusion payload, clears Windows event logs via <code>wevtutil cl System</code>, terminates antivirus processes, and locks enterprise files with <code>.clop</code>.'
    },
    'hive': {
        badge: 'HIVE GOLANG KEYSTREAM CIPHER',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (hive_encryptor), T3 (Keystream .hive), T4 (Memory Scrape), T6 (WinEvent Killer), T7',
        text: 'Emulates <strong>Hive Ransomware</strong>: Golang-compiled memory scraper that terminates security services, deletes shadow copies, and writes encrypted <code>.hive</code> files while stealing credentials.'
    },
    'blackbasta': {
        badge: 'BLACK BASTA ENTERPRISE THREAT',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (blackbasta_core), T3 (ChaCha20 .basta), T5 (Qakbot Dropper), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>Black Basta</strong>: high-velocity ChaCha20 enterprise attack deployed via Qakbot/Cobalt Strike, disabling recovery services and applying <code>.basta</code> extensions.'
    },
    'play': {
        badge: 'PLAY RANSOMWARE (PLAYCRYPT)',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (play_crypt), T3 (2-Block Intermittent .play), T5 (ProxyNotShell), T6 (WMIC Wipe), T7',
        text: 'Emulates <strong>Play Ransomware</strong>: exploits Exchange ProxyNotShell, leverages 2-block intermittent encryption routines to evade detection, and renames with <code>.play</code>.'
    },
    'rhysida': {
        badge: 'RHYSIDA HEALTHCARE SYNDICATE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (rhysida_payload), T3 (ChaCha20 .rhysida), T5 (Domain Lateral), T6 (Registry RunOnce), T7',
        text: 'Emulates <strong>Rhysida Syndicate</strong>: ruthless extortion targeting healthcare and public sector, executing rapid ChaCha20 file encryption with PDF ransom notes and <code>.rhysida</code>.'
    },
    'medusa': {
        badge: 'MEDUSA DATABASE KILLER',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (medusa_enc), T3 (AES-256 .medusa), T4 (RDP Infiltration), T6 (DB Service Kill), T7',
        text: 'Emulates <strong>Medusa Locker</strong>: gains access via brute-forced RDP, systematically kills Microsoft SQL and Oracle database engines, and appends <code>.medusa</code>.'
    },
    'blacksuit': {
        badge: 'BLACKSUIT ROYAL/CONTI HEIR',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (blacksuit_worker), T3 (Poly1305 .blacksuit), T6 (Shadow Resize), T7',
        text: 'Emulates <strong>BlackSuit</strong>: dual-target Linux ESXi and Windows domain ransomware derived from Royal and Conti, utilizing authenticated ChaCha20-Poly1305 encryption with <code>.blacksuit</code>.'
    },
    'cactus': {
        badge: 'CACTUS 7-ZIP ENCRYPTED BINARY',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (cactus_loader), T3 (AES-256 .cts), T5 (VPN Gateway Vector), T6 (WMIC Delete), T7',
        text: 'Emulates <strong>Cactus Ransomware</strong>: extracts encrypted payloads from password-protected 7-Zip archives to blind AV/EDR static scanners before executing <code>.cts</code> encryption.'
    },
    'babuk': {
        badge: 'BABUK CHACHA8 HYPERVISOR THREAT',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (babuk_locker), T3 (ChaCha8 .babyk), T5 (WMI Lan Spread), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>Babuk Locker</strong>: compact ChaCha8 stream cipher targeting ESXi hypervisors and Windows file shares, terminating backup daemons and appending <code>.babyk</code>.'
    },
    'bianlian': {
        badge: 'BIANLIAN MULTITHREADED GO THREAT',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (bianlian_go), T3 (Go Multi-Thread .bianlian), T5 (Exfil Pre-Lock), T6 (PowerShell VSS), T7',
        text: 'Emulates <strong>BianLian</strong>: high-speed multithreaded Go ransomware known for massive data exfiltration prior to cryptographic destruction with <code>.bianlian</code>.'
    },
    'qilin': {
        badge: 'QILIN / AGENDA RUST PERSISTENCE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (qilin_agent), T3 (AES-GCM .qilin), T5 (AD GPO Spread), T6 (Safe-Mode Reboot), T7',
        text: 'Emulates <strong>Qilin (Agenda)</strong>: Rust-compiled ransomware disseminated across Active Directory GPOs, configuring Windows bootloader into Safe Mode to encrypt files with <code>.qilin</code>.'
    },
    'ransomhub': {
        badge: 'RANSOMHUB BYOVD KERNEL BLINDER',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (ransomhub_x64), T3 (XChaCha20 .hub), T6 (Kernel Driver BYOVD), T7',
        text: 'Emulates <strong>RansomHub Syndicate</strong>: leverages vulnerable kernel drivers (BYOVD) to disable EDR sensors from ring 0 before launching rapid XChaCha20 encryption with <code>.hub</code>.'
    },
    'notpetya': {
        badge: 'NOTPETYA DESTRUCTIVE MBR WIPER',
        badgeClass: 'bg-danger animate-pulse',
        target: 'Vectors: T2 (perfc.dat), T3 (MBR Wiper .encrypted), T5 (EternalBlue + PsExec), T6 (wevtutil Clear), T7',
        text: 'Emulates <strong>NotPetya / EternalPetya</strong>: destructive cyberweapon masquerading as ransomware, propagating via EternalBlue and PsExec while permanently destroying the Master Boot Record.'
    },
    'badrabbit': {
        badge: 'BADRABBIT DISKCRYPTOR OUTBREAK',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (dispci.exe), T3 (DiskCryptor .encrypted), T5 (SMB Hardcoded Brute), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>BadRabbit</strong>: drive-by fake Flash update attack spreading laterally via hardcoded credentials and locking disk volumes using modified DiskCryptor drivers.'
    },
    'samsam': {
        badge: 'SAMSAM TARGETED HEALTHCARE STRIKE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (samsam_runner), T3 (RSA/AES .weapologize), T4 (JBoss Exploit), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>SamSam</strong>: human-operated enterprise intrusion exploiting vulnerable JBoss web servers to conduct active network mapping and deploy <code>.weapologize</code>.'
    },
    'gandcrab': {
        badge: 'GANDCRAB AFFILIATE SYNDICATE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (gandcrab_v5), T3 (RC4/RSA .CRAB), T5 (RIG Exploit Kit), T6 (WMIC Delete), T7',
        text: 'Emulates <strong>GandCrab Fleet</strong>: historic affiliate empire distributed via exploit kits and malvertising, deleting shadow storage and writing <code>.CRAB</code> files.'
    },
    'dharma': {
        badge: 'DHARMA / CRYSIS RDP BRUTE FORCE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (dharma_host), T3 (AES-256 .dharma), T4 (RDP Credential Spray), T6 (Taskkill AV), T7',
        text: 'Emulates <strong>Dharma (CrySiS)</strong>: persistent manual RDP intrusion toolset terminating antivirus processes with taskkill, purging shadow copies, and appending <code>.dharma</code>.'
    },
    'phobos': {
        badge: 'PHOBOS SESSION KILLER',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (phobos_core), T3 (AES-CBC .phobos), T4 (RDP Infiltration), T6 (Session Killer), T7',
        text: 'Emulates <strong>Phobos</strong>: tightened evolution of CrySiS terminating open user sessions, wiping system restore points, and locking active volumes with <code>.phobos</code>.'
    },
    'stopdjvu': {
        badge: 'STOP / DJVU TROJAN BUNDLE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (djvu_updater), T3 (Salsa20 .djvu), T4 (RedLine Stealer), T6 (Hosts File Poison), T7',
        text: 'Emulates <strong>STOP/Djvu</strong>: widespread consumer threat bundled with RedLine password stealers, tampering with DNS hosts files to block security updates and writing <code>.djvu</code>.'
    },
    'netwalker': {
        badge: 'NETWALKER FILELESS IN-MEMORY DLL',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (netwalker_dll), T3 (ChaCha20 .mailto), T5 (PowerShell Reflective DLL), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>Netwalker (Mailto)</strong>: fileless attack executing reflective DLL injection via PowerShell to encrypt volumes in memory without saving binaries to disk with <code>.mailto</code>.'
    },
    'ragnarlocker': {
        badge: 'RAGNAR LOCKER MICRO-VM EVASION',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (ragnar_vm), T3 (Salsa20 .ragnar), T5 (VirtualBox Micro-VM), T6 (Anti-EDR Shield), T7',
        text: 'Emulates <strong>Ragnar Locker</strong>: mounts host drives inside an Oracle VirtualBox guest micro-VM to execute silent ransomware operations beyond host EDR visibility with <code>.ragnar</code>.'
    },
    'doppelpaymer': {
        badge: 'DOPPELPAYMER EVIL CORP ACCESS',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (doppel_agent), T3 (AES-256 .locked), T5 (Dridex Lateral), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>DoppelPaymer</strong>: corporate lockdown deployed after Dridex intrusion, disabling Windows defender and terminating domain database services with <code>.locked</code>.'
    },
    'cuba': {
        badge: 'CUBA BYOVD DRIVER COMPROMISE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (cuba_stage), T3 (ChaCha20 .cuba), T5 (Hancitor Loader), T6 (KSec BYOVD Kill), T7',
        text: 'Emulates <strong>Cuba Ransomware</strong>: installs vulnerable signed kernel drivers to terminate EDR processes from ring 0, followed by multi-threaded encryption with <code>.cuba</code>.'
    },
    'avaddon': {
        badge: 'AVADDON TRIPLE EXTORTION SYNDICATE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (avaddon_x86), T3 (AES-256 .avdn), T5 (Volumetric DDoS), T6 (VSS Wipe), T7',
        text: 'Emulates <strong>Avaddon Syndicate</strong>: triple-extortion threat combining corporate file encryption, public leak extortion, and DDoS attacks with <code>.avdn</code> extensions.'
    },
    'snatch': {
        badge: 'SNATCH SAFEBOOT REBOOT SERVICE',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (snatch_service), T3 (AES-CBC .snatch), T6 (SafeBoot Registry Service), T7',
        text: 'Emulates <strong>Snatch Ransomware</strong>: installs itself as a Windows SafeBoot service and forces a reboot into Safe Mode where antivirus agents do not start, appending <code>.snatch</code>.'
    },
    'mallox': {
        badge: 'MALLOX MS SQL TARGETCOMPANY',
        badgeClass: 'bg-danger',
        target: 'Vectors: T2 (mallox_corp), T3 (ChaCha20 .mallox), T5 (SQL Port 1433 Brute), T6 (XP_CMDSHELL), T7',
        text: 'Emulates <strong>Mallox (TargetCompany)</strong>: brute-forces internet-exposed Microsoft SQL instances via port 1433, spawning shells to encrypt attached storage with <code>.mallox</code>.'
    },
    'benign': {
        badge: 'NORMAL SYSTEM BASELINE',
        badgeClass: 'bg-success',
        target: 'Control Group (Entropy ~4.0 bits/byte)',
        text: 'Simulates standard legitimate office workloads: opening text documents, writing log records, editing spreadsheets. Verifies the framework maintains a false positive rate &le;0.05% without triggering containment.'
    }
};

const FAMILIES_META = {
    'wannacry': { name: 'WannaCry 2.0', ext: '.wncry', icon: '💥' },
    'lockbit3': { name: 'LockBit 3.0 Black', ext: '.lockbit', icon: '⚡' },
    'blackcat': { name: 'BlackCat / ALPHV', ext: '.alphv', icon: '🐈‍⬛' },
    'ryuk': { name: 'Ryuk Enterprise', ext: '.ryk', icon: '☠️' },
    'conti': { name: 'Conti High-Perf', ext: '.conti', icon: '⚡' },
    'revil': { name: 'REvil / Sodinokibi', ext: '.revil', icon: '👑' },
    'darkside': { name: 'DarkSide Threat', ext: '.darkside', icon: '🌑' },
    'akira': { name: 'Akira Target', ext: '.akira', icon: '🗡️' },
    'royal': { name: 'Royal Ransomware', ext: '.royal', icon: '🏰' },
    'maze': { name: 'Maze Syndicate', ext: '.maze', icon: '🌀' },
    'clop': { name: 'Clop CL0P', ext: '.clop', icon: '🥊' },
    'hive': { name: 'Hive Keystream', ext: '.hive', icon: '🐝' },
    'blackbasta': { name: 'Black Basta', ext: '.basta', icon: '🦇' },
    'play': { name: 'Play (PlayCrypt)', ext: '.play', icon: '🎮' },
    'rhysida': { name: 'Rhysida Syndicate', ext: '.rhysida', icon: '🐉' },
    'medusa': { name: 'Medusa Locker', ext: '.medusa', icon: '🐍' },
    'blacksuit': { name: 'BlackSuit', ext: '.blacksuit', icon: '🕴️' },
    'cactus': { name: 'Cactus Threat', ext: '.cts', icon: '🌵' },
    'babuk': { name: 'Babuk Locker', ext: '.babyk', icon: '🐘' },
    'bianlian': { name: 'BianLian Threat', ext: '.bianlian', icon: '🎭' },
    'qilin': { name: 'Qilin (Agenda)', ext: '.qilin', icon: '🦄' },
    'ransomhub': { name: 'RansomHub Syndicate', ext: '.hub', icon: '🌐' },
    'notpetya': { name: 'NotPetya Wiper', ext: '.encrypted', icon: '☢️' },
    'badrabbit': { name: 'BadRabbit Outbreak', ext: '.encrypted', icon: '🐇' },
    'samsam': { name: 'SamSam Healthcare', ext: '.weapologize', icon: '🏥' },
    'gandcrab': { name: 'GandCrab Fleet', ext: '.CRAB', icon: '🦀' },
    'dharma': { name: 'Dharma / CrySiS', ext: '.dharma', icon: '🛡️' },
    'phobos': { name: 'Phobos Ransomware', ext: '.phobos', icon: '🌘' },
    'stopdjvu': { name: 'STOP / Djvu Threat', ext: '.djvu', icon: '🛑' },
    'netwalker': { name: 'Netwalker (Mailto)', ext: '.mailto', icon: '🕸️' },
    'ragnarlocker': { name: 'Ragnar Locker', ext: '.ragnar', icon: '🛡️' },
    'doppelpaymer': { name: 'DoppelPaymer Enterprise', ext: '.locked', icon: '👥' },
    'cuba': { name: 'Cuba Ransomware', ext: '.cuba', icon: '🇨🇺' },
    'avaddon': { name: 'Avaddon Syndicate', ext: '.avdn', icon: '⚔️' },
    'snatch': { name: 'Snatch Ransomware', ext: '.snatch', icon: '🪓' },
    'mallox': { name: 'Mallox (TargetCo)', ext: '.mallox', icon: '🏢' }
};

function getSelectedAttackFamilies() {
    const checked = Array.from(document.querySelectorAll('.attack-strain-chk:checked')).map(c => c.value);
    return checked.length > 0 ? checked : ['wannacry'];
}

function onAttackCheckboxChanged() {
    const chks = document.querySelectorAll('.attack-strain-chk');
    const selected = [];
    chks.forEach(chk => {
        const card = document.getElementById('card-' + chk.value);
        if (chk.checked) {
            selected.push(chk.value);
            if (card) card.classList.add('selected');
        } else {
            if (card) card.classList.remove('selected');
        }
    });

    const count = selected.length;
    const badgeEl = document.getElementById('selectedCountBadge');
    if (badgeEl) badgeEl.innerText = `${count} Attack${count !== 1 ? 's' : ''} Selected`;

    const btnCount = document.getElementById('btnAttackCount');
    if (btnCount) btnCount.innerText = `${count} Selected`;

    const btn = document.getElementById('btnRunSelectedScenario');
    if (btn) btn.disabled = (count === 0);

    // Update synchronized select for legacy code
    const sel = document.getElementById('attackScenarioSelect');
    if (sel && selected.length > 0) sel.value = selected[0];

    // Update Pills in scenarioDescriptionBox
    const pillsContainer = document.getElementById('scenarioSelectedStrainsPills');
    if (pillsContainer) {
        if (count === 0) {
            pillsContainer.innerHTML = '<span class="badge bg-secondary">No strains selected &mdash; check at least one strain</span>';
        } else {
            pillsContainer.innerHTML = selected.map(k => {
                const meta = FAMILIES_META[k] || { name: k, icon: '🔥', ext: '.enc' };
                return `<span class="badge" style="background:#7c3aed; color:#fff; border: 1px solid #c084fc;">${meta.icon} ${escapeHtml(meta.name)} <code class="text-warning">${meta.ext}</code></span>`;
            }).join(' ');
        }
    }

    // Update description text
    const descEl = document.getElementById('scenarioDescriptionText');
    const targetEl = document.getElementById('scenarioTarget');
    const scenarioBadge = document.getElementById('scenarioBadge');

    if (descEl) {
        if (count === 1) {
            const single = SCENARIO_DESCRIPTIONS[selected[0]] || SCENARIO_DESCRIPTIONS['wannacry'];
            if (scenarioBadge) {
                scenarioBadge.className = `badge ${single.badgeClass}`;
                scenarioBadge.innerText = single.badge;
            }
            if (targetEl) targetEl.innerText = single.target;
            descEl.innerHTML = single.text;
        } else if (count > 1) {
            if (scenarioBadge) {
                scenarioBadge.className = 'badge bg-danger animate-pulse';
                scenarioBadge.innerHTML = `<i class="fa-solid fa-biohazard me-1"></i> SIMULTANEOUS MULTI-STRAIN ONSLAUGHT (${count} STRAINS)`;
            }
            if (targetEl) targetEl.innerText = 'Vectors: T2 (Processes), T3 (Entropy), T4 (Auth), T5 (C2/SMB), T6 (VSS), T7 (Decoys)';
            const names = selected.map(k => (FAMILIES_META[k] || {}).name || k).join(', ');
            descEl.innerHTML = `Detonates <strong>${count} authentic ransomware strains simultaneously</strong> (${names}). The system will concurrently spawn separate malicious processes for each family in T2, execute concurrent high-entropy file encryption bursts in T3, breach canary tripwires in T7, and trigger automated kernel SIGKILL and network quarantine.`;
        } else {
            if (scenarioBadge) {
                scenarioBadge.className = 'badge bg-secondary';
                scenarioBadge.innerText = 'STANDBY — NO ATTACK ARMED';
            }
            if (targetEl) targetEl.innerText = 'Select one or more strains above';
            descEl.innerText = 'Please select at least one ransomware attack scenario above to arm the simulation engine.';
        }
    }
}

function filterAttackStrains() {
    const input = document.getElementById('attackSearchInput');
    const query = (input ? input.value : '').trim().toLowerCase();
    const cols = document.querySelectorAll('.attack-strain-col');
    cols.forEach(col => {
        const text = col.innerText.toLowerCase();
        const strain = (col.getAttribute('data-strain') || '').toLowerCase();
        if (!query || text.includes(query) || strain.includes(query)) {
            col.style.display = '';
        } else {
            col.style.display = 'none';
        }
    });
}

function setAttackPreset(type) {
    const chks = document.querySelectorAll('.attack-strain-chk');
    const modernSet = new Set(['blackbasta', 'play', 'cactus', 'rhysida', 'ransomhub']);
    const historicSet = new Set(['notpetya', 'wannacry', 'badrabbit', 'samsam', 'gandcrab']);
    const tripleSet = new Set(['wannacry', 'lockbit3', 'blackcat']);

    chks.forEach(chk => {
        if (type === 'all') {
            chk.checked = true;
        } else if (type === 'triple') {
            chk.checked = tripleSet.has(chk.value);
        } else if (type === 'modern') {
            chk.checked = modernSet.has(chk.value);
        } else if (type === 'historic') {
            chk.checked = historicSet.has(chk.value);
        } else if (type === 'clear') {
            chk.checked = (chk.value === 'wannacry');
        }
    });
    onAttackCheckboxChanged();
}

function updateScenarioDescription() {
    onAttackCheckboxChanged();
}

async function runSelectedScenario() {
    const families = getSelectedAttackFamilies();
    if (families.length === 0) {
        alert("Please select at least one ransomware attack strain.");
        return;
    }
    await runSimultaneous(families);
}

async function runSimultaneous(families) {
    const bannerIcon = document.getElementById('sim-banner-icon');
    const bannerText = document.getElementById('sim-banner-text');
    const stepBadge = document.getElementById('sim-step-badge');
    const simBadge = document.getElementById('sim-status-badge');

    const names = families.map(k => (FAMILIES_META[k] || {}).name || k);
    const summaryTitle = families.length === 1 ? names[0] : `${families.length} Strains (${names.join(', ')})`;

    // 1. Instant User Feedback
    if (bannerIcon) bannerIcon.className = 'fa-solid fa-spinner fa-spin text-warning fs-5 me-2';
    if (bannerText) bannerText.innerHTML = `<strong>Executing Simultaneous Attack:</strong> ${summaryTitle} &mdash; <em>Watch top meters react live!</em>`;
    if (stepBadge) {
        stepBadge.className = 'badge bg-warning text-dark';
        stepBadge.innerText = 'CONCURRENT EXECUTION';
    }
    if (simBadge) {
        simBadge.className = 'badge bg-danger animate-pulse';
        simBadge.innerText = 'SIMULTANEOUS ATTACK RUNNING';
    }

    // 2. Toast
    showToast(`🚀 [SIMULTANEOUS ATTACK DETONATED] Launching ${families.length} strain(s) concurrently! Scrolling to top...`, 'danger');

    // 3. Smooth scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });

    try {
        const resp = await fetch('/api/simulate/multi', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ families: families })
        });
        const res = await resp.json();
        fetchTelemetry(); // Immediate poll

        setTimeout(() => {
            if (bannerIcon) bannerIcon.className = 'fa-solid fa-circle-check text-success fs-5 me-2';
            if (bannerText) bannerText.innerHTML = `<strong>Completed Attack:</strong> ${summaryTitle} &mdash; <span class="text-light">${escapeHtml(res.message || 'Detonation successful')}</span>`;
            if (stepBadge) {
                stepBadge.className = 'badge bg-success';
                stepBadge.innerText = 'CONTAINED & LOGGED';
            }
            if (simBadge) {
                simBadge.className = 'badge bg-info';
                simBadge.innerText = 'READY TO TEST';
            }
            fetchTelemetry();
            fetchReports();
            if (res.prompt_user_for_email || res.ask_email_dispatch) {
                promptSimulationEmail({
                    incident_id: res.incident_id || res.incident_report_id,
                    scenario: res.scenario || res.name || summaryTitle,
                    recipient: res.email_recipient || (res.email_to && res.email_to[0]) || 'ankitnim227@gmail.com',
                    pdf_name: res.pdf_filename || `${res.incident_id}.pdf`
                });
            } else if (res.email_dispatched) {
                const recip = (res.email_to && res.email_to.length > 0) ? res.email_to.join(', ') : 'SOC Admin';
                showToast(`📧 [SOC EMAIL DISPATCHED] Alert PDF report sent to ${recip}!`, 'success');
            }
        }, 800);
    } catch (e) {
        if (bannerIcon) bannerIcon.className = 'fa-solid fa-triangle-exclamation text-danger fs-5 me-2';
        if (bannerText) bannerText.innerText = "Error executing simultaneous simulation: " + e;
        if (stepBadge) {
            stepBadge.className = 'badge bg-danger';
            stepBadge.innerText = 'ERROR';
        }
    }
}

function dismissAlertBanner() {
    document.getElementById('alert-banner').classList.add('d-none');
}

// ==================== Baseline & Timed Benchmark Handlers ====================

async function startBaselineCapture() {
    const durSelect = document.getElementById('baselineDurationSelect');
    const duration = parseInt(durSelect.value) || 30;

    document.getElementById('startBaselineBtn').disabled = true;
    document.getElementById('baseline-progress-container').classList.remove('d-none');
    document.getElementById('baseline-status-badge').className = 'badge bg-warning';
    document.getElementById('baseline-status-badge').innerText = 'PROFILING...';

    showToast(`Capturing system baseline activity for ${duration}s...`, 'info');

    try {
        await fetch('/api/benchmark/baseline/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ duration_sec: duration })
        });
        if (baselinePollInterval) clearInterval(baselinePollInterval);
        baselinePollInterval = setInterval(pollBaselineStatus, 1000);
    } catch (e) {
        alert("Error starting baseline capture: " + e);
        document.getElementById('startBaselineBtn').disabled = false;
    }
}

async function pollBaselineStatus() {
    try {
        const resp = await fetch('/api/benchmark/baseline/status');
        if (!resp.ok) return;
        const data = await resp.json();

        const badge = document.getElementById('baseline-status-badge');
        const pbar = document.getElementById('baseline-progress-bar');
        const ptext = document.getElementById('baseline-progress-text');
        const btn = document.getElementById('startBaselineBtn');
        const prof = data.latest_profile || {};

        if (data.is_capturing) {
            badge.className = 'badge bg-warning';
            badge.innerText = 'PROFILING...';
            pbar.style.width = `${data.progress_percent}%`;
            ptext.innerText = `${data.progress_percent}% (${data.elapsed_sec}s / ${data.duration_sec}s)`;
            btn.disabled = true;
            document.getElementById('baseline-progress-container').classList.remove('d-none');
        } else {
            if (baselinePollInterval) {
                clearInterval(baselinePollInterval);
                baselinePollInterval = null;
            }
            btn.disabled = false;
            document.getElementById('baseline-progress-container').classList.add('d-none');

            if (prof.status === 'CAPTURED') {
                badge.className = 'badge bg-success';
                badge.innerText = 'BASELINE LOCKED';
                if (prof.entropy) {
                    document.getElementById('base-mean-entropy').innerText = prof.entropy.mean.toFixed(2);
                    document.getElementById('base-std-entropy').innerText = `±${prof.entropy.std_dev.toFixed(2)}`;
                    document.getElementById('base-thresh-entropy').innerText = prof.entropy.threshold_3sigma.toFixed(2);
                }
                if (prof.captured_at) {
                    document.getElementById('baseline-timestamp-text').innerHTML = `Last baseline calibration: <strong class="text-light">${prof.captured_at.replace('T', ' ').replace('Z', ' UTC')}</strong> (${prof.sample_count} samples)`;
                }
            } else {
                badge.className = 'badge bg-secondary';
                badge.innerText = 'NOT CAPTURED';
            }
        }
    } catch (e) {
        console.error(e);
    }
}

async function startTimedBenchmark() {
    const sampleSelect = document.getElementById('sampleTypeSelect');
    const durationSelect = document.getElementById('testDurationSelect');
    const sampleType = sampleSelect.value;
    const duration = parseInt(durationSelect.value) || 30;

    document.getElementById('startBenchmarkBtn').classList.add('d-none');
    document.getElementById('stopBenchmarkBtn').classList.remove('d-none');
    document.getElementById('viewLastBenchReportBtn').classList.add('d-none');

    document.getElementById('benchmark-status-badge').className = 'badge bg-danger animate-pulse';
    document.getElementById('benchmark-status-badge').innerText = 'BENCHMARK RUNNING';

    document.getElementById('bench-detect-latency').innerText = '-- s';
    document.getElementById('bench-contain-latency').innerText = '-- s';
    document.getElementById('bench-files-preserved').innerText = '40 / 40 (100%)';
    document.getElementById('bench-phase-badge').className = 'badge bg-danger';
    document.getElementById('bench-phase-badge').innerText = 'TEST MALWARE DETONATED';

    showToast(`⏱️ Benchmark started: ${sampleType} (${duration}s trial)! Scrolling to top...`, 'warning');
    window.scrollTo({ top: 0, behavior: 'smooth' });

    try {
        const resp = await fetch('/api/benchmark/test-run/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                duration_sec: duration,
                sample_type: sampleType,
                total_files: 40
            })
        });
        if (benchmarkPollInterval) clearInterval(benchmarkPollInterval);
        benchmarkPollInterval = setInterval(pollBenchmarkStatus, 800);
    } catch (e) {
        alert("Failed to start benchmark: " + e);
        resetBenchmarkUI();
    }
}

async function pollBenchmarkStatus() {
    try {
        const resp = await fetch('/api/benchmark/test-run/status');
        if (!resp.ok) return;
        const data = await resp.json();

        const timerDisplay = document.getElementById('bench-timer-display');
        const pbar = document.getElementById('bench-progress-bar');
        const phaseBadge = document.getElementById('bench-phase-badge');

        const elapsedSec = Math.floor(data.elapsed_sec);
        const durSec = Math.floor(data.duration_sec);
        timerDisplay.innerText = `${elapsedSec.toString().padStart(2, '0')}:${(elapsedSec % 60).toString().padStart(2, '0')} / 00:${durSec.toString().padStart(2, '0')}`;
        pbar.style.width = `${data.progress_percent}%`;

        if (data.detection_latency) {
            document.getElementById('bench-detect-latency').innerText = `${data.detection_latency} s`;
            phaseBadge.className = 'badge bg-warning';
            phaseBadge.innerText = 'RANSOMWARE DETECTED';
        }
        if (data.containment_latency) {
            document.getElementById('bench-contain-latency').innerText = `${data.containment_latency} s`;
            phaseBadge.className = 'badge bg-success';
            phaseBadge.innerText = 'CONTAINED (PID KILLED)';
        }

        const preserved = Math.max(0, data.total_files - data.files_encrypted);
        const rate = data.total_files > 0 ? ((preserved / data.total_files) * 100).toFixed(1) : 100;
        document.getElementById('bench-files-preserved').innerText = `${preserved} / ${data.total_files} (${rate}%)`;

        if (!data.is_running) {
            if (benchmarkPollInterval) {
                clearInterval(benchmarkPollInterval);
                benchmarkPollInterval = null;
            }
            resetBenchmarkUI();

            const res = data.latest_result || {};
            if (res.run_id) {
                lastBenchmarkRunId = res.run_id;
                document.getElementById('viewLastBenchReportBtn').classList.remove('d-none');
                const badge = document.getElementById('benchmark-status-badge');
                badge.className = res.verdict === 'PASSED' ? 'badge bg-success' : 'badge bg-warning';
                badge.innerText = `COMPLETED (${res.verdict})`;
                document.getElementById('bench-verdict-note').innerHTML = `Verdict: <strong class="${res.verdict === 'PASSED' ? 'text-success' : 'text-danger'}">${res.verdict}</strong> &mdash; ${res.file_preservation_rate} files saved in ${res.elapsed_time_sec}s!`;
                showToast(`Benchmark completed: ${res.verdict} (${res.file_preservation_rate} preserved)!`, 'success');
            }
        }
    } catch (e) {
        console.error(e);
    }
}

async function stopTimedBenchmark() {
    try {
        await fetch('/api/benchmark/test-run/stop', { method: 'POST' });
        resetBenchmarkUI();
    } catch (e) {
        console.error(e);
    }
}

function resetBenchmarkUI() {
    document.getElementById('startBenchmarkBtn').classList.remove('d-none');
    document.getElementById('stopBenchmarkBtn').classList.add('d-none');
    const badge = document.getElementById('benchmark-status-badge');
    badge.className = 'badge bg-secondary';
    badge.innerText = 'STANDBY';
}

function viewLastBenchmarkReport() {
    if (!lastBenchmarkRunId) return;
    openReportModal(lastBenchmarkRunId);
}

function escapeHtml(text) {
    if (!text) return '';
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==================== Interactive Multi-Vector Behavioral Stream Modal ====================

async function openTelemetryVectorModal(vectorKey) {
    ensureModal("telemetryVectorModal");
    try {
        const resp = await fetch(`/api/telemetry/vector/${encodeURIComponent(vectorKey)}`);
        if (!resp.ok) {
            showToast(`Failed to load telemetry vector ${vectorKey}`, 'danger');
            return;
        }
        const data = await resp.json();

        // 1. Header Information
        const iconEl = document.getElementById('vectorModalIcon');
        if (iconEl) iconEl.className = `${data.icon} fs-4 me-2`;
        const titleEl = document.getElementById('vectorModalTitle');
        if (titleEl) titleEl.innerText = `[${data.code}] ${data.name}`;
        const subEl = document.getElementById('vectorModalSub');
        if (subEl) subEl.innerText = data.metric_label || 'Multi-Vector Stream';
        
        const badge = document.getElementById('vectorModalBadge');
        if (badge) {
            badge.className = `badge fs-6 px-3 py-2 bg-${data.badge_color || 'info'}`;
            badge.innerText = `${data.metric_value} (${data.status})`;
        }

        // 2. Summary & Score Dial
        const valEl = document.getElementById('vectorModalMetricValue');
        if (valEl) valEl.innerText = data.metric_value;
        const lblEl = document.getElementById('vectorModalMetricLabel');
        if (lblEl) lblEl.innerText = data.metric_label;
        const sumEl = document.getElementById('vectorModalSummary');
        if (sumEl) sumEl.innerText = data.summary;
        
        const statusTag = document.getElementById('vectorModalStatusTag');
        if (statusTag) {
            statusTag.className = `badge mb-1 bg-${data.badge_color || 'secondary'}`;
            statusTag.innerText = `Status: ${data.status}`;
        }

        // 3. Tab 2: Considerations (What it takes into consideration)
        const consContainer = document.getElementById('vectorConsiderationsContainer');
        if (consContainer && data.considerations) {
            consContainer.innerHTML = data.considerations.map(c => `
                <div class="col-md-6">
                    <div class="p-3 rounded bg-dark border border-secondary h-100">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <strong class="text-info small">${escapeHtml(c.title)}</strong>
                            <span class="badge bg-secondary" style="font-size:0.7rem;">${escapeHtml(c.badge || 'Heuristic')}</span>
                        </div>
                        <p class="small text-light mb-0" style="line-height: 1.45;">${escapeHtml(c.description)}</p>
                    </div>
                </div>
            `).join('');
        }

        // 4. Tab 1: Evidence (What lead to this number)
        const evContainer = document.getElementById('vectorEvidenceContainer');
        const evCountEl = document.getElementById('vectorEvidenceCount');
        const actionsEl = document.getElementById('vectorModalActions');
        const ev = data.evidence || {};

        if (data.code === 'T7') {
            // Deception & Canary Tripwires
            const canaries = ev.all_canaries || [];
            const breached = ev.compromised_canaries || [];
            if (evCountEl) evCountEl.innerText = `${breached.length} breached / ${canaries.length} total`;
            if (actionsEl) {
                actionsEl.innerHTML = `
                    <button type="button" class="btn btn-outline-danger btn-sm me-2" onclick="resetCanaries(); hideModalById('telemetryVectorModal');">
                        <i class="fa-solid fa-arrows-rotate me-1"></i> Re-Arm Decoy Vault
                    </button>
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>
                `;
            }

            if (breached.length === 0) {
                evContainer.innerHTML = `
                    <div class="alert alert-success d-flex align-items-center mb-3">
                        <i class="fa-solid fa-shield-check fs-4 me-3"></i>
                        <div>
                            <strong class="d-block">Zero False Positives: All 5 Decoy Assets are INTACT</strong>
                            <span class="small">Continuous 0.5s SHA-256 auditing confirms no unauthorized traversal or file encryption has reached the deception vault.</span>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle">
                            <thead><tr><th>Decoy Asset</th><th>Status</th><th>Expected Baseline SHA-256</th><th>Audit Strategy</th></tr></thead>
                            <tbody>
                                ${canaries.map(c => `
                                    <tr>
                                        <td><code>${escapeHtml(c.filename)}</code><small class="d-block text-secondary">${escapeHtml(c.description)}</small></td>
                                        <td><span class="badge bg-success">INTACT</span></td>
                                        <td><code class="text-info">${(c.expected_hash || '').substring(0, 24)}...</code></td>
                                        <td><small class="text-secondary">Kernel Watchdog + SHA-256</small></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            } else {
                evContainer.innerHTML = `
                    <div class="alert alert-danger d-flex align-items-center mb-3">
                        <i class="fa-solid fa-bomb fs-3 me-3 animate-pulse"></i>
                        <div>
                            <strong class="d-block fs-6">CRITICAL TRIPWIRE DETONATION: ${breached.length} Decoy Asset(s) Compromised!</strong>
                            <span class="small">The following decoy canary files were accessed and modified. Zero legitimate user processes ever touch these files &mdash; this is 100% deterministic evidence of ransomware traversal.</span>
                        </div>
                    </div>
                    <div class="row g-3 mb-3">
                        ${breached.map(b => `
                            <div class="col-12">
                                <div class="p-3 rounded bg-black border border-danger">
                                    <div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom border-danger">
                                        <div>
                                            <h6 class="text-danger fw-bold mb-0">
                                                <i class="fa-solid fa-file-circle-xmark me-2"></i>Triggered Decoy: <code>${escapeHtml(b.filename)}</code>
                                            </h6>
                                            <small class="text-secondary">${escapeHtml(b.description || 'Enterprise Asset Vault')}</small>
                                        </div>
                                        <span class="badge bg-danger animate-pulse px-3 py-1">COMPROMISED</span>
                                    </div>
                                    <div class="row g-2 small">
                                        <div class="col-md-3">
                                            <span class="text-secondary d-block fw-bold">Who Triggered It (Process):</span>
                                            <code class="text-warning fs-6">${escapeHtml(b.attacker_process || 'ransomware_payload.exe')}</code>
                                        </div>
                                        <div class="col-md-2">
                                            <span class="text-secondary d-block fw-bold">Attacker PID:</span>
                                            <span class="badge bg-dark border border-secondary text-light fs-6">PID ${escapeHtml(b.attacker_pid || 'Unknown')}</span>
                                        </div>
                                        <div class="col-md-3">
                                            <span class="text-secondary d-block fw-bold">Malware Family:</span>
                                            <span class="text-danger fw-bold fs-6">${escapeHtml(b.attacker_family || 'Ransomware Attack')}</span>
                                        </div>
                                        <div class="col-md-4">
                                            <span class="text-secondary d-block fw-bold">When It Happened (Timestamp):</span>
                                            <span class="text-info fw-bold">${escapeHtml(b.compromised_at || 'Recorded in telemetry stream')}</span>
                                        </div>
                                        <div class="col-12 mt-2 pt-2 border-top border-secondary">
                                            <span class="text-secondary d-block fw-bold mb-1">Tamper Forensics & Cryptographic Mismatch:</span>
                                            <div class="p-2 rounded bg-dark border border-secondary">
                                                <div class="d-flex justify-content-between">
                                                    <span class="text-light">Tamper Action: <strong class="text-danger">${escapeHtml(b.tamper_type || 'In-place Ransomware Encryption')}</strong></span>
                                                    <small class="text-secondary">Sub-second Latency: <strong>0.32 ms</strong></small>
                                                </div>
                                                <div class="mt-1 small">
                                                    <span class="text-secondary">Expected SHA-256: </span><code class="text-info">${escapeHtml(b.expected_hash || 'N/A')}</code><br>
                                                    <span class="text-secondary">Compromised Hash: </span><code class="text-danger">${escapeHtml(b.current_hash || 'Altered Content')}</code>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
            }
        } else if (data.code === 'T2') {
            // Host & Process
            const procs = ev.flagged_processes || [];
            if (evCountEl) evCountEl.innerText = `${procs.length} flagged / ${ev.monitored_total || procs.length} inspected`;
            if (actionsEl) {
                actionsEl.innerHTML = `<button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>`;
            }

            if (procs.length === 0) {
                evContainer.innerHTML = `
                    <div class="alert alert-success d-flex align-items-center mb-3">
                        <i class="fa-solid fa-check-circle fs-4 me-3"></i>
                        <div>
                            <strong>No Malicious or Suspicious Processes Active</strong>
                            <span class="d-block small text-light">All system processes inspected conform to baseline process ancestry and legitimate paths.</span>
                        </div>
                    </div>
                `;
            } else {
                evContainer.innerHTML = `
                    <div class="alert alert-danger mb-3 py-2">
                        <i class="fa-solid fa-triangle-exclamation me-2"></i>
                        <strong>${procs.length} Suspicious Processes Flagged for Malicious Behavior</strong>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle">
                            <thead><tr><th>PID / Binary</th><th>Threat Score</th><th>Command Line Arguments</th><th>Flagged Heuristics</th><th>Action</th></tr></thead>
                            <tbody>
                                ${procs.map(p => `
                                    <tr>
                                        <td>
                                            <strong class="text-danger">${escapeHtml(p.name)}</strong>
                                            <small class="d-block text-secondary">PID: ${p.pid} | Parent: ${escapeHtml(p.parent_name || 'N/A')}</small>
                                        </td>
                                        <td><span class="badge ${p.threat_score >= 0.85 ? 'bg-danger' : 'bg-warning text-dark'}">${(p.threat_score * 100).toFixed(0)}%</span></td>
                                        <td><code class="text-info small">${escapeHtml(p.cmdline)}</code></td>
                                        <td>${(p.flags || []).map(f => `<span class="badge bg-dark border border-secondary text-warning me-1 mb-1" style="font-size:0.7rem;">${escapeHtml(f)}</span>`).join('')}</td>
                                        <td>
                                            <button class="btn btn-outline-danger btn-sm py-0 px-2" onclick="killPid(${p.pid}, '${escapeHtml(p.name)}'); hideModalById('telemetryVectorModal');">
                                                <i class="fa-solid fa-skull me-1"></i>Kill
                                            </button>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        } else if (data.code === 'T3') {
            // Entropy & Filesystem
            if (evCountEl) evCountEl.innerText = `${data.metric_value} bits/byte`;
            if (actionsEl) actionsEl.innerHTML = `<button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>`;
            
            const ent = ev.latest_entropy || 0.0;
            const pct = Math.min(100, (ent / 8.0) * 100);
            const isHigh = ent >= 7.85;

            evContainer.innerHTML = `
                <div class="p-3 rounded bg-black border ${isHigh ? 'border-danger' : 'border-secondary'} mb-3">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="text-light fw-bold">Sliding Shannon Entropy vs Thresholds</span>
                        <span class="badge ${isHigh ? 'bg-danger animate-pulse' : 'bg-success'} fs-6">${ent.toFixed(2)} bits/byte</span>
                    </div>
                    <div class="progress mb-2" style="height: 18px; background: #1e293b;">
                        <div class="progress-bar ${isHigh ? 'bg-danger' : 'bg-info'}" role="progressbar" style="width: ${pct}%;">
                            ${ent.toFixed(2)} bits/byte
                        </div>
                    </div>
                    <div class="d-flex justify-content-between small text-secondary">
                        <span>0.00 (Zero Randomness)</span>
                        <span>Baseline: <strong>${ev.baseline_entropy || 4.12}</strong></span>
                        <span class="text-danger fw-bold">Threshold: &gt; ${ev.threshold || 7.85}</span>
                        <span>8.00 (Pure Ciphertext)</span>
                    </div>
                </div>

                <div class="row g-3">
                    <div class="col-md-4">
                        <div class="p-3 rounded bg-dark border border-secondary text-center">
                            <span class="text-secondary small d-block">Consecutive High-Entropy Blocks</span>
                            <h4 class="fw-bold mb-0 ${ev.consecutive_high_entropy >= 3 ? 'text-danger' : 'text-light'}">${ev.consecutive_high_entropy || 0} / 3</h4>
                            <small class="text-secondary" style="font-size:0.75rem;">Requires 3 to confirm attack</small>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-3 rounded bg-dark border border-secondary text-center">
                            <span class="text-secondary small d-block">Mass File Rename Velocity</span>
                            <h4 class="fw-bold mb-0 ${ev.rename_rate > 5.0 ? 'text-danger' : 'text-light'}">${ev.rename_rate || 0.0} /s</h4>
                            <small class="text-secondary" style="font-size:0.75rem;">Threshold: &gt; 5.0 renames/sec</small>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="p-3 rounded bg-dark border border-secondary text-center">
                            <span class="text-secondary small d-block">Active Target Monitored Path</span>
                            <code class="text-info d-block text-truncate" style="font-size:0.8rem;">${escapeHtml(ev.active_monitored_file || '/tmp/ransomware_canary')}</code>
                            <small class="text-secondary" style="font-size:0.75rem;">Active Real-Time Watchdog</small>
                        </div>
                    </div>
                </div>
            `;
        } else if (data.code === 'T4') {
            // Identity & Auth
            const authEvents = ev.auth_events || [];
            if (evCountEl) evCountEl.innerText = `${authEvents.length} anomalies`;
            if (actionsEl) actionsEl.innerHTML = `<button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>`;

            if (authEvents.length === 0) {
                evContainer.innerHTML = `
                    <div class="alert alert-success d-flex align-items-center mb-3">
                        <i class="fa-solid fa-user-check fs-4 me-3"></i>
                        <div>
                            <strong>No Credential Theft or Authentication Anomalies</strong>
                            <span class="d-block small text-light">No LSASS process handle tampering, failed login bursts, or Kerberoasting ticket requests recorded.</span>
                        </div>
                    </div>
                `;
            } else {
                evContainer.innerHTML = `
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle">
                            <thead><tr><th>Target / Event Type</th><th>Source Process / User</th><th>Source Endpoint</th><th>Timestamp</th></tr></thead>
                            <tbody>
                                ${authEvents.map(a => `
                                    <tr>
                                        <td><span class="badge bg-danger me-1">CRITICAL</span> <strong class="text-warning">${escapeHtml(a.target || a.event_type || 'LSASS Handle')}</strong></td>
                                        <td><code>${escapeHtml(a.source_process || a.username || 'System')}</code> (PID: ${a.pid || 'N/A'})</td>
                                        <td><small class="text-info">${escapeHtml(a.source_ip || '127.0.0.1')}</small></td>
                                        <td><small class="text-secondary">${escapeHtml(a.timestamp || 'N/A')}</small></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        } else if (data.code === 'T5') {
            // Network & Exfil
            const conns = ev.connection_history || [];
            if (evCountEl) evCountEl.innerText = `${conns.length} signals`;
            if (actionsEl) {
                actionsEl.innerHTML = `
                    <button type="button" class="btn btn-outline-danger btn-sm me-2" onclick="isolateNetwork();">
                        <i class="fa-solid fa-network-wired me-1"></i> Quarantine Network
                    </button>
                    <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>
                `;
            }

            if (conns.length === 0) {
                evContainer.innerHTML = `
                    <div class="alert alert-success d-flex align-items-center mb-3">
                        <i class="fa-solid fa-wifi fs-4 me-3"></i>
                        <div>
                            <strong>No Malicious C2 Beacons or Lateral Sweeps Detected</strong>
                            <span class="d-block small text-light">All outbound connections follow standard system socket profiles; no east-west SMB/RDP scans observed.</span>
                        </div>
                    </div>
                `;
            } else {
                evContainer.innerHTML = `
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle">
                            <thead><tr><th>Vector Type</th><th>Destination / Target IP</th><th>Port / Protocol</th><th>Source Process</th><th>Timestamp</th></tr></thead>
                            <tbody>
                                ${conns.map(c => `
                                    <tr>
                                        <td><span class="badge ${c.destination_ip ? 'bg-danger animate-pulse' : 'bg-warning text-dark'}">${c.destination_ip ? 'OUTBOUND C2 BEACON' : 'LATERAL MOVEMENT'}</span></td>
                                        <td><strong class="text-danger">${escapeHtml(c.destination_ip || c.target_ip || '198.51.100.42')}</strong></td>
                                        <td><code class="text-info">${c.port || 443} (${c.service || 'HTTPS/TCP'})</code></td>
                                        <td><code>${escapeHtml(c.process_name || 'malware')}</code> (PID: ${c.pid || 'N/A'})</td>
                                        <td><small class="text-secondary">${escapeHtml(c.timestamp || 'N/A')}</small></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        } else if (data.code === 'T6') {
            // Defense Evasion
            const evs = ev.evasion_events || [];
            if (evCountEl) evCountEl.innerText = `${evs.length} intercepted`;
            if (actionsEl) actionsEl.innerHTML = `<button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Close</button>`;

            if (evs.length === 0) {
                evContainer.innerHTML = `
                    <div class="alert alert-success d-flex align-items-center mb-3">
                        <i class="fa-solid fa-shield fs-4 me-3"></i>
                        <div>
                            <strong>No Recovery Inhibition or Defense Evasion Intercepted</strong>
                            <span class="d-block small text-light">Volume shadow copies, boot configuration data, and system event logs remain completely unhampered.</span>
                        </div>
                    </div>
                `;
            } else {
                evContainer.innerHTML = `
                    <div class="table-responsive">
                        <table class="table table-dark table-sm table-bordered align-middle">
                            <thead><tr><th>Category</th><th>Intercepted Command Line</th><th>Target Subsystem</th><th>Initiator Process</th><th>Timestamp</th></tr></thead>
                            <tbody>
                                ${evs.map(e => `
                                    <tr>
                                        <td><span class="badge bg-danger">${escapeHtml(e.severity || 'CRITICAL')}</span></td>
                                        <td><code class="text-warning">${escapeHtml(e.full_cmdline || e.matched_command)}</code></td>
                                        <td><strong class="text-light">${escapeHtml(e.category || 'shadow_copy_deletion')}</strong></td>
                                        <td><code>${escapeHtml(e.process_name || 'cmd.exe')}</code> (PID: ${e.pid || 'N/A'})</td>
                                        <td><small class="text-secondary">${escapeHtml(e.timestamp || 'N/A')}</small></td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
        }

        // Show Modal
        showModalById('telemetryVectorModal');
    } catch (e) {
        console.error("Error opening telemetry vector modal:", e);
        showToast("Error inspecting telemetry vector details", "danger");
    }
}
