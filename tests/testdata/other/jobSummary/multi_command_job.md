#### Builds
| Status | Id | Details |
|--------|----|---------|
| ✅ | build-name (build-number) |  |
| ❌ | build-name (build-number) | <pre>Violations: <b>4</b> - (2 Security, 1 License, 1 Operational)</pre> |
#### Artifacts
| Status | Id | Details |
|--------|----|---------|
| ❌ | /binary-name | <pre>Security Vulnerabilities: <b>3</b> (3 unique)<br>└── 3 Secrets 🔴 <span style="color:red">2 High</span><br>              🟡 <span style="color:yellow">1 Low</span></pre> |
| ✅ | other-root/dir/binary-name2 |  |
#### Modules
| Status | Id | Details |
|--------|----|---------|
| ❌ | /application1 | <pre>Security Vulnerabilities: <b>14</b> (12 unique)<br>├── 1 SAST 🟡 <span style="color:yellow">1 Low</span><br>├── 5 IAC 🟠 <span style="color:orange">5 Medium</span><br>└── 8 SCA ❗️ <span style="color:red">3 Critical</span> (2 Not Applicable)<br>          🔴 <span style="color:red">4 High</span> (1 Applicable, 1 Not Applicable)<br>          🟡 <span style="color:yellow">1 Low</span></pre> |
| ❌ | /application2 | <pre>Violations: <b>1</b> - (1 Security)<br>Security Vulnerabilities: <b>1</b> (1 unique)<br>└── 1 SCA 🔴 <span style="color:red">1 High</span> (1 Not Applicable)</pre> |
| ✅ | /dir/application3 |  |
#### Curation
| Status | Id | Details |
|--------|----|---------|
| ❌ | /application1 | <pre>Total Number of Packages: <b>6</b><br>🟢 Total Number of Approved Packages: <b>4</b><br>🔴 Total Number of Blocked Packages: <b>2</b><br>├── Policy: cvss_score, Condition:cvss score higher than 4.0 (1)<br>└── Policy: Malicious, Condition: Malicious package (1)</pre> |
| ❌ | /application2 | <pre>Total Number of Packages: <b>6</b><br>🟢 Total Number of Approved Packages: <b>4</b><br>🔴 Total Number of Blocked Packages: <b>2</b><br>├── Policy: License, Condition: GPL (1)<br>└── Policy: Aged, Condition: Package is aged (1)</pre> |