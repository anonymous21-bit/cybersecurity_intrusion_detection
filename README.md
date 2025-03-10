# cybersecurity_intrusion_detection

##Result

Starting IREP Algorithm...

Growing Phase - Rules before pruning:
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and ip_reputation_score <= 0.60 => Class 0
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and ip_reputation_score > 0.60 => Class 1
  Rule: failed_logins <= 2.50 and login_attempts > 6.50 => Class 1
  Rule: failed_logins > 2.50 => Class 1

Pruning Phase - Rules after pruning:
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and ip_reputation_score > 0.60 => Class 1, error=0.0000, coverage=177
  Rule: failed_logins <= 2.50 and login_attempts > 6.50 => Class 1, error=0.0000, coverage=221
  Rule: failed_logins > 2.50 => Class 1, error=0.0000, coverage=401
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and ip_reputation_score <= 0.60 => Class 0, error=0.1891, coverage=1719
Growing Phase - Rules before pruning:
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and browser_type <= 3.50 => Class 0
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and browser_type > 3.50 => Class 1
  Rule: failed_logins <= 2.50 and login_attempts > 6.50 => Class 1
  Rule: failed_logins > 2.50 => Class 1

Pruning Phase - Rules after pruning:
  Rule: failed_logins <= 2.50 and login_attempts > 6.50 => Class 1, error=0.0000, coverage=221
  Rule: failed_logins > 2.50 => Class 1, error=0.0000, coverage=401
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and browser_type <= 3.50 => Class 0, error=0.2453, coverage=1802
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and browser_type > 3.50 => Class 1, error=0.3617, coverage=94
Growing Phase - Rules before pruning:
  Rule: failed_logins <= 2.50 and browser_type <= 3.50 and session_duration <= 1102.12 => Class 0
  Rule: failed_logins <= 2.50 and browser_type <= 3.50 and session_duration > 1102.12 => Class 0
  Rule: failed_logins <= 2.50 and browser_type > 3.50 and login_attempts <= 3.50 => Class 0
  Rule: failed_logins <= 2.50 and browser_type > 3.50 and login_attempts > 3.50 => Class 1
  Rule: failed_logins > 2.50 => Class 1

Pruning Phase - Rules after pruning:
  Rule: failed_logins <= 2.50 and browser_type > 3.50 and login_attempts > 3.50 => Class 1, error=0.0000, coverage=56
  Rule: failed_logins > 2.50 => Class 1, error=0.0000, coverage=401
  Rule: failed_logins <= 2.50 and browser_type > 3.50 and login_attempts <= 3.50 => Class 0, error=0.2273, coverage=44
  Rule: failed_logins <= 2.50 and browser_type <= 3.50 and session_duration <= 1102.12 => Class 0, error=0.3144, coverage=1530
  Rule: failed_logins <= 2.50 and browser_type <= 3.50 and session_duration > 1102.12 => Class 0, error=0.3614, coverage=487
Growing Phase - Rules before pruning:
  Rule: failed_logins <= 2.50 and session_duration <= 1102.12 and ip_reputation_score <= 0.35 => Class 0
  Rule: failed_logins <= 2.50 and session_duration <= 1102.12 and ip_reputation_score > 0.35 => Class 0
  Rule: failed_logins <= 2.50 and session_duration > 1102.12 and session_duration <= 1105.59 => Class 1
  Rule: failed_logins <= 2.50 and session_duration > 1102.12 and session_duration > 1105.59 => Class 0
  Rule: failed_logins > 2.50 => Class 1

Pruning Phase - Rules after pruning:
  Rule: failed_logins > 2.50 => Class 1, error=0.0000, coverage=401
  Rule: failed_logins <= 2.50 and session_duration <= 1102.12 and ip_reputation_score <= 0.35 => Class 0, error=0.2787, coverage=897
  Rule: failed_logins <= 2.50 and session_duration > 1102.12 and session_duration > 1105.59 => Class 0, error=0.3703, coverage=505
  Rule: failed_logins <= 2.50 and session_duration <= 1102.12 and ip_reputation_score > 0.35 => Class 0, error=0.3992, coverage=709
  Rule: failed_logins <= 2.50 and session_duration > 1102.12 and session_duration <= 1105.59 => Class 1, error=0.5000, coverage=6
Growing Phase - Rules before pruning:
  Rule: session_duration <= 1102.12 and ip_reputation_score <= 0.35 and network_packet_size <= 1101.50 => Class 0
  Rule: session_duration <= 1102.12 and ip_reputation_score <= 0.35 and network_packet_size > 1101.50 => Class 1
  Rule: session_duration <= 1102.12 and ip_reputation_score > 0.35 and ip_reputation_score <= 0.35 => Class 1
  Rule: session_duration <= 1102.12 and ip_reputation_score > 0.35 and ip_reputation_score > 0.35 => Class 0
  Rule: session_duration > 1102.12 and session_duration <= 1105.59 and session_duration <= 1103.62 => Class 0
  Rule: session_duration > 1102.12 and session_duration <= 1105.59 and session_duration > 1103.62 => Class 1
  Rule: session_duration > 1102.12 and session_duration > 1105.59 and session_duration <= 2550.52 => Class 0
  Rule: session_duration > 1102.12 and session_duration > 1105.59 and session_duration > 2550.52 => Class 0

Pruning Phase - Rules after pruning:
  Rule: session_duration <= 1102.12 and ip_reputation_score <= 0.35 and network_packet_size <= 1101.50 => Class 0, error=0.3856, coverage=1053
  Rule: session_duration > 1102.12 and session_duration > 1105.59 and session_duration <= 2550.52 => Class 0, error=0.4831, coverage=532
  Rule: session_duration <= 1102.12 and ip_reputation_score > 0.35 and ip_reputation_score > 0.35 => Class 0, error=0.4904, coverage=836
  Rule: session_duration > 1102.12 and session_duration <= 1105.59 and session_duration <= 1103.62 => Class 0, error=0.5000, coverage=2
  Rule: session_duration > 1102.12 and session_duration <= 1105.59 and session_duration > 1103.62 => Class 1, error=0.5000, coverage=4
  Rule: session_duration > 1102.12 and session_duration > 1105.59 and session_duration > 2550.52 => Class 0, error=0.5275, coverage=91
Growing Phase - Rules before pruning:
  Rule: session_duration <= 2550.52 and network_packet_size <= 225.50 and session_duration <= 890.88 => Class 0
  Rule: session_duration <= 2550.52 and network_packet_size <= 225.50 and session_duration > 890.88 => Class 0
  Rule: session_duration <= 2550.52 and network_packet_size > 225.50 and ip_reputation_score <= 0.42 => Class 0
  Rule: session_duration <= 2550.52 and network_packet_size > 225.50 and ip_reputation_score > 0.42 => Class 0
  Rule: session_duration > 2550.52 and unusual_time_access <= 0.50 and login_attempts <= 1.50 => Class 1
  Rule: session_duration > 2550.52 and unusual_time_access <= 0.50 and login_attempts > 1.50 => Class 0
  Rule: session_duration > 2550.52 and unusual_time_access > 0.50 => Class 1

Pruning Phase - Rules after pruning:
  Rule: session_duration > 2550.52 and unusual_time_access > 0.50 => Class 1, error=0.0000, coverage=18
  Rule: session_duration <= 2550.52 and network_packet_size > 225.50 and ip_reputation_score <= 0.42 => Class 0, error=0.3840, coverage=1521
  Rule: session_duration > 2550.52 and unusual_time_access <= 0.50 and login_attempts > 1.50 => Class 0, error=0.4265, coverage=68
  Rule: session_duration <= 2550.52 and network_packet_size <= 225.50 and session_duration <= 890.88 => Class 0, error=0.4965, coverage=143
  Rule: session_duration <= 2550.52 and network_packet_size > 225.50 and ip_reputation_score > 0.42 => Class 0, error=0.5497, coverage=704
  Rule: session_duration <= 2550.52 and network_packet_size <= 225.50 and session_duration > 890.88 => Class 0, error=0.5763, coverage=59
Growing Phase - Rules before pruning:
  Rule: network_packet_size <= 225.50 and login_attempts <= 4.50 and session_duration <= 1014.66 => Class 0
  Rule: network_packet_size <= 225.50 and login_attempts <= 4.50 and session_duration > 1014.66 => Class 0
  Rule: network_packet_size <= 225.50 and login_attempts > 4.50 and ip_reputation_score <= 0.55 => Class 0
  Rule: network_packet_size <= 225.50 and login_attempts > 4.50 and ip_reputation_score > 0.55 => Class 1
  Rule: network_packet_size > 225.50 and session_duration <= 300.53 and session_duration <= 38.21 => Class 0
  Rule: network_packet_size > 225.50 and session_duration <= 300.53 and session_duration > 38.21 => Class 0
  Rule: network_packet_size > 225.50 and session_duration > 300.53 and session_duration <= 304.16 => Class 1
  Rule: network_packet_size > 225.50 and session_duration > 300.53 and session_duration > 304.16 => Class 0

Pruning Phase - Rules after pruning:
  Rule: network_packet_size <= 225.50 and login_attempts > 4.50 and ip_reputation_score > 0.55 => Class 1, error=0.2308, coverage=13
  Rule: network_packet_size > 225.50 and session_duration <= 300.53 and session_duration > 38.21 => Class 0, error=0.4279, coverage=610
  Rule: network_packet_size > 225.50 and session_duration > 300.53 and session_duration > 304.16 => Class 0, error=0.4401, coverage=1595
  Rule: network_packet_size <= 225.50 and login_attempts <= 4.50 and session_duration <= 1014.66 => Class 0, error=0.4565, coverage=92
  Rule: network_packet_size > 225.50 and session_duration <= 300.53 and session_duration <= 38.21 => Class 0, error=0.5000, coverage=100
  Rule: network_packet_size <= 225.50 and login_attempts > 4.50 and ip_reputation_score <= 0.55 => Class 0, error=0.5385, coverage=65
  Rule: network_packet_size <= 225.50 and login_attempts <= 4.50 and session_duration > 1014.66 => Class 0, error=0.5833, coverage=36
Growing Phase - Rules before pruning:
  Rule: session_duration <= 260.18 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0
  Rule: session_duration <= 260.18 and session_duration <= 38.21 and session_duration > 35.63 => Class 1
  Rule: session_duration <= 260.18 and session_duration > 38.21 and encryption_used <= 1.50 => Class 0
  Rule: session_duration <= 260.18 and session_duration > 38.21 and encryption_used > 1.50 => Class 0
  Rule: session_duration > 260.18 and session_duration <= 265.64 and session_duration <= 263.92 => Class 0
  Rule: session_duration > 260.18 and session_duration <= 265.64 and session_duration > 263.92 => Class 1
  Rule: session_duration > 260.18 and session_duration > 265.64 and ip_reputation_score <= 0.55 => Class 0
  Rule: session_duration > 260.18 and session_duration > 265.64 and ip_reputation_score > 0.55 => Class 0

Pruning Phase - Rules after pruning:
  Rule: session_duration > 260.18 and session_duration <= 265.64 and session_duration <= 263.92 => Class 0, error=0.3000, coverage=10
  Rule: session_duration > 260.18 and session_duration > 265.64 and ip_reputation_score <= 0.55 => Class 0, error=0.3950, coverage=1562
  Rule: session_duration > 260.18 and session_duration <= 265.64 and session_duration > 263.92 => Class 1, error=0.4286, coverage=7
  Rule: session_duration <= 260.18 and session_duration > 38.21 and encryption_used <= 1.50 => Class 0, error=0.4295, coverage=475
  Rule: session_duration <= 260.18 and session_duration > 38.21 and encryption_used > 1.50 => Class 0, error=0.4513, coverage=113
  Rule: session_duration <= 260.18 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0, error=0.4811, coverage=106
  Rule: session_duration <= 260.18 and session_duration <= 38.21 and session_duration > 35.63 => Class 1, error=0.5000, coverage=6
  Rule: session_duration > 260.18 and session_duration > 265.64 and ip_reputation_score > 0.55 => Class 0, error=0.7992, coverage=239
Growing Phase - Rules before pruning:
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration > 35.63 => Class 1
  Rule: session_duration <= 300.53 and session_duration > 38.21 and ip_reputation_score <= 0.37 => Class 0
  Rule: session_duration <= 300.53 and session_duration > 38.21 and ip_reputation_score > 0.37 => Class 0
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration <= 303.35 => Class 1
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration > 303.35 => Class 0
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score <= 0.55 => Class 1
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score > 0.55 => Class 0

Pruning Phase - Rules after pruning:
  Rule: session_duration <= 300.53 and session_duration > 38.21 and ip_reputation_score <= 0.37 => Class 0, error=0.3769, coverage=390
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration > 303.35 => Class 0, error=0.3945, coverage=1498
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0, error=0.4811, coverage=106
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration > 35.63 => Class 1, error=0.5000, coverage=6
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration <= 303.35 => Class 1, error=0.5000, coverage=4
  Rule: session_duration <= 300.53 and session_duration > 38.21 and ip_reputation_score > 0.37 => Class 0, error=0.5160, coverage=281
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score > 0.55 => Class 0, error=0.7940, coverage=233
Growing Phase - Rules before pruning:
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration > 35.63 => Class 1
  Rule: session_duration <= 300.53 and session_duration > 38.21 and session_duration <= 64.60 => Class 0
  Rule: session_duration <= 300.53 and session_duration > 38.21 and session_duration > 64.60 => Class 0
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration <= 303.35 => Class 1
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration > 303.35 => Class 0
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score <= 0.55 => Class 1
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score > 0.55 => Class 0

Pruning Phase - Rules after pruning:
  Rule: session_duration <= 300.53 and session_duration > 38.21 and session_duration <= 64.60 => Class 0, error=0.3667, coverage=90
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration > 303.35 => Class 0, error=0.3945, coverage=1498
  Rule: session_duration <= 300.53 and session_duration > 38.21 and session_duration > 64.60 => Class 0, error=0.4458, coverage=581
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration <= 35.63 => Class 0, error=0.4811, coverage=106
  Rule: session_duration <= 300.53 and session_duration <= 38.21 and session_duration > 35.63 => Class 1, error=0.5000, coverage=6
  Rule: session_duration > 300.53 and ip_reputation_score <= 0.55 and session_duration <= 303.35 => Class 1, error=0.5000, coverage=4
  Rule: session_duration > 300.53 and ip_reputation_score > 0.55 and ip_reputation_score > 0.55 => Class 0, error=0.7940, coverage=233

Final Ruleset:
  Rule: failed_logins <= 2.50 and login_attempts <= 6.50 and ip_reputation_score > 0.60 => Class 1
  Rule: failed_logins <= 2.50 and login_attempts > 6.50 => Class 1
  Rule: failed_logins <= 2.50 and browser_type > 3.50 and login_attempts > 3.50 => Class 1
  Rule: failed_logins > 2.50 => Class 1
  Rule: session_duration <= 1102.12 and ip_reputation_score <= 0.35 and network_packet_size <= 1101.50 => Class 0
  Rule: session_duration > 2550.52 and unusual_time_access > 0.50 => Class 1
  Rule: network_packet_size <= 225.50 and login_attempts > 4.50 and ip_reputation_score > 0.55 => Class 1
  Rule: session_duration > 260.18 and session_duration <= 265.64 and session_duration <= 263.92 => Class 0
  Rule: session_duration <= 300.53 and session_duration > 38.21 and ip_reputation_score <= 0.37 => Class 0
  Rule: session_duration <= 300.53 and session_duration > 38.21 and session_duration <= 64.60 => Class 0

Final Accuracy on Test Set: 0.8947
