/* Worked examples. Illustrative inputs written for this page, not data from the thesis experiments. */
window.ECX_EXAMPLES = [
  {
    id: "exfil",
    label: "Data exfiltration (bytes out, ratio, cloud upload)",
    note: "An anomaly detector fires on a workstation that sent 4.2 GB out in one hour. Off-hours activity carries " +
          "the most model weight but is common in normal traffic, and endpoint telemetry was never collected.",
    alert: { title: "Large outbound transfer from WS-0142", detector: "Isolation forest on hourly flow features",
             score: 0.91, threshold: 0.80, tactic: "exfiltration", k: 3 },
    items: [
      { name: "bytes_out_gb_1h", value: "4.2", direction: "higher",
        baseline: "0.02 0.03 0.05 0.05 0.08 0.1 0.1 0.12 0.15 0.18 0.2 0.22 0.25 0.3 0.3 0.35 0.4 0.42 0.5 0.55 " +
                  "0.6 0.65 0.7 0.8 0.85 0.9 1.0 1.1 1.2 1.3 1.5 1.6 1.8 2.0 2.2 2.5 2.8 3.1 3.5 5.1",
        source: "Netflow", techniques: "T1048, T1030", attribution: "0.30" },
      { name: "out_to_in_byte_ratio", value: "18", direction: "higher",
        baseline: "0.1 0.15 0.2 0.2 0.25 0.3 0.3 0.35 0.4 0.4 0.5 0.5 0.6 0.6 0.7 0.8 0.9 1.0 1.0 1.1 " +
                  "1.2 1.3 1.5 1.6 1.8 2.0 2.2 2.5 2.8 3.0 3.4 3.8 4.2 5.0 5.5 6.0 7.5 9.0 12 25",
        source: "Netflow", techniques: "T1048", attribution: "0.10" },
      { name: "new_external_destination", value: "1", direction: "higher", baseline: "12%",
        source: "Web proxy", techniques: "T1041", attribution: "0.10" },
      { name: "off_hours", value: "1", direction: "higher", baseline: "35%",
        source: "Netflow", techniques: "", attribution: "0.45" },
      { name: "upload_to_cloud_storage", value: "1", direction: "higher", baseline: "4%",
        source: "Web proxy", techniques: "T1567.002", attribution: "0.05" },
      { name: "dns_queries_1h", value: "310", direction: "higher",
        baseline: "40 60 80 95 110 130 150 170 200 220 240 260 300 320 350 400 450 500 600 700 800 900 1100 1300 1600",
        source: "DNS logs", techniques: "T1048.003", attribution: "0" }
    ],
    sources: [
      { name: "Netflow", state: "collected", components: "Network Traffic Flow, Network Connection Creation" },
      { name: "Web proxy", state: "collected", components: "Network Traffic Content" },
      { name: "DNS logs", state: "collected", components: "Network Traffic Content" },
      { name: "EDR", state: "not_collected", components: "Process Creation, Command Execution, File Access" },
      { name: "Cloud storage audit", state: "query_failed", components: "Cloud Storage Access" }
    ]
  },
  {
    id: "lateral",
    label: "Lateral movement (NTLM shortcut)",
    note: "A supervised model flags a logon. Its top attribution is NTLM, which 23.4% of normal logons also use. " +
          "The page demotes NTLM and shows the specific evidence instead.",
    alert: { title: "Suspicious logon U4821 → C1709", detector: "Gradient boosting on authentication events",
             score: 0.97, threshold: 0.50, tactic: "lateral-movement", k: 3 },
    items: [
      { name: "auth_type_ntlm", value: "1", direction: "higher", baseline: "23.4%",
        source: "Windows authentication logs", techniques: "T1550.002", attribution: "0.62" },
      { name: "new_src_dst_pair", value: "1", direction: "higher", baseline: "3%",
        source: "Windows authentication logs", techniques: "T1021", attribution: "0.14" },
      { name: "user_distinct_dst_24h", value: "14", direction: "higher",
        baseline: "1 1 1 1 1 1 2 2 2 2 2 2 2 3 3 3 3 3 4 4 4 4 5 5 5 6 6 7 8 9 10 12 15 20 1 2 3 1 2 1",
        source: "Windows authentication logs", techniques: "T1021", attribution: "0.12" },
      { name: "src_logons_1h", value: "9", direction: "higher",
        baseline: "0 0 1 1 1 1 1 2 2 2 2 2 3 3 3 3 4 4 4 5 5 5 6 6 7 7 8 10 12 3 2 1 1 0 2 3 4 1 2 1",
        source: "Netflow", techniques: "T1021", attribution: "0.07" },
      { name: "logon_type_network", value: "1", direction: "higher", baseline: "61%",
        source: "Windows authentication logs", techniques: "T1021", attribution: "0.05" }
    ],
    sources: [
      { name: "Windows authentication logs", state: "collected",
        components: "Logon Session Creation, User Account Authentication, Active Directory Credential Request" },
      { name: "Netflow", state: "collected", components: "Network Traffic Flow, Network Connection Creation" },
      { name: "EDR process telemetry", state: "not_collected",
        components: "Process Creation, Command Execution, Module Load" },
      { name: "File share audit", state: "not_collected", components: "Network Share Access" }
    ]
  },
  {
    id: "spray",
    label: "Password spraying (rule, no attribution)",
    note: "A threshold rule fires on many failed sign-ins across many accounts. A rule has no attribution, so M2 " +
          "and M7 are not computed. The domain-controller query failed.",
    alert: { title: "Password spray from 203.0.113.45", detector: "Rule: >50 failed sign-ins over >20 accounts in 10 min",
             score: 0.88, threshold: 0.70, tactic: "credential-access", k: 3 },
    items: [
      { name: "failed_signins_10m", value: "220", direction: "higher",
        baseline: "0 0 0 0 1 1 1 1 1 2 2 2 2 3 3 3 4 4 5 5 6 6 7 8 9 10 12 0 1 2 0 1 1 0 2 3 1 0 1 40",
        source: "IdP sign-in logs", techniques: "T1110.003", attribution: "" },
      { name: "distinct_accounts_failed_10m", value: "180", direction: "higher",
        baseline: "1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 3 3 3 3 4 4 5 1 1 1 2 1 1 2 1 1 3 1 2",
        source: "IdP sign-in logs", techniques: "T1110.003", attribution: "" },
      { name: "success_after_failures", value: "1", direction: "higher", baseline: "2%",
        source: "IdP sign-in logs", techniques: "T1078", attribution: "" },
      { name: "seconds_between_attempts", value: "3.1", direction: "lower",
        baseline: "3 6 9 12 15 20 25 30 35 40 45 60 75 90 120 150 180 240 300 360 420 480 540 600 900",
        source: "IdP sign-in logs", techniques: "T1110.003", attribution: "" },
      { name: "source_ip_new_to_tenant", value: "1", direction: "higher", baseline: "20%",
        source: "IdP sign-in logs", techniques: "", attribution: "" }
    ],
    sources: [
      { name: "IdP sign-in logs", state: "collected",
        components: "User Account Authentication, Logon Session Creation, Logon Session Metadata" },
      { name: "Application logs", state: "collected_empty", components: "Application Log Content" },
      { name: "Domain controller logs", state: "query_failed",
        components: "Active Directory Credential Request, User Account Authentication" }
    ]
  },
  {
    id: "weak",
    label: "Weak explanation (common, off-threat evidence)",
    note: "A model tuned for lateral movement fires on a service-account sign-in. Its evidence is common in " +
          "normal activity, points to other tactics, and the model's top features differ from the specific ones.",
    alert: { title: "Unusual sign-in for svc-backup", detector: "Anomaly model aimed at lateral movement",
             score: 0.78, threshold: 0.75, tactic: "lateral-movement", k: 3 },
    items: [
      { name: "mfa_prompts_1h", value: "4", direction: "higher", baseline: "9%",
        source: "IdP sign-in logs", techniques: "T1621", attribution: "0.02" },
      { name: "new_device", value: "1", direction: "higher", baseline: "18%",
        source: "IdP sign-in logs", techniques: "T1078", attribution: "0.03" },
      { name: "country_change", value: "1", direction: "higher", baseline: "12%",
        source: "IdP sign-in logs", techniques: "T1078", attribution: "0.05" },
      { name: "off_hours", value: "1", direction: "higher", baseline: "35%",
        source: "IdP sign-in logs", techniques: "", attribution: "0.30" },
      { name: "vpn_login", value: "1", direction: "higher", baseline: "45%",
        source: "VPN logs", techniques: "T1133", attribution: "0.30" },
      { name: "service_account", value: "1", direction: "higher", baseline: "50%",
        source: "IdP sign-in logs", techniques: "T1078", attribution: "0.30" }
    ],
    sources: [
      { name: "IdP sign-in logs", state: "collected",
        components: "User Account Authentication, Logon Session Creation, Logon Session Metadata" },
      { name: "VPN logs", state: "collected", components: "Logon Session Creation, Network Traffic Flow" }
    ]
  },
  {
    id: "beacon",
    label: "C2 beaconing (regular HTTPS callbacks)",
    note: "A detector flags very regular HTTPS callbacks to a young domain. TLS content is not inspected, so " +
          "part of the evidence ATT&CK expects is a blind spot.",
    alert: { title: "Periodic HTTPS callbacks from WS-0077", detector: "Beacon score on proxy sessions",
             score: 0.83, threshold: 0.75, tactic: "command-and-control", k: 3 },
    items: [
      { name: "interval_jitter_cv", value: "0.04", direction: "lower",
        baseline: "0.05 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9 1.0 1.1 1.2 1.3 1.4 1.5 1.6 1.8 2.0 2.2 2.5",
        source: "Web proxy", techniques: "T1071.001", attribution: "0.35" },
      { name: "domain_age_days", value: "6", direction: "lower",
        baseline: "3 40 90 150 200 300 400 500 700 900 1200 1500 1800 2200 2600 3000 3500 4000 5000 6000",
        source: "Web proxy", techniques: "T1071.001", attribution: "0.25" },
      { name: "connections_24h", value: "288", direction: "higher",
        baseline: "5 10 20 30 40 50 60 80 100 120 150 180 200 250 300 350 400 500 700 900",
        source: "Netflow", techniques: "T1071.001", attribution: "0.20" },
      { name: "rare_user_agent", value: "1", direction: "higher", baseline: "8%",
        source: "Web proxy", techniques: "T1071.001", attribution: "0.10" },
      { name: "small_uniform_payloads", value: "1", direction: "higher", baseline: "15%",
        source: "Netflow", techniques: "T1071.001", attribution: "0.10" }
    ],
    sources: [
      { name: "Web proxy", state: "collected", components: "Network Traffic Flow" },
      { name: "Netflow", state: "collected", components: "Network Traffic Flow, Network Connection Creation" }
    ]
  }
];
