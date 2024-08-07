<details open>
<summary><h2>🔒 Security Scans Summary</h2></summary>
<h3>Binary Artifact Scans</h3>

| ID  | Filename | Security Violations | Security Issues |
|-----|----------|---------------------|-----------------|
| 1   | <a href="https://soleng.jfrog.io/ui/onDemandScanning/dbf1b0dd-0c38-4969-6fd5-2d93056540d3" target="_blank">resources/sampler-v1.3.0.zip</a> | <pre>No Watch is defined</pre> | <pre>Security Vulnerabilities: <b>4</b><br>└── 4 SCA 🔴 <span style="color:red">4 High</span></pre> |
| 2   | <a href="https://soleng.jfrog.io/ui/onDemandScanning/dbf1b0dd-0c38-4969-6fd5-2d93056540d3" target="_blank">resources/sampler-v1.3.0.zip</a> | <pre>Watch: XXX, YYY, ZZZ</pre> <pre>Security Violations: <b>4</b><br>└── 4 SCA 🔴 <span style="color:red">4 High</span></pre>  | <pre>Security Vulnerabilities: <b>4</b><br>└── 4 SCA 🔴 <span style="color:red">4 High</span></pre> |
| 3   | <a href="https://soleng.jfrog.io/ui/onDemandScanning/dbf1b0dd-0c38-4969-6fd5-2d93056540d3" target="_blank">resources/sampler-v1.3.0.zip</a> | <pre>Watch: XXX, YYY, ZZZ</pre> <pre>0 Policy Violations</pre>  | <pre>Security Vulnerabilities: <b>4</b><br>└── 4 SCA 🔴 <span style="color:red">4 High</span></pre> |

</details>

<details open>

<h3>Build-info Scans</h3>

| ID  | Build name | Security Violations | Security Issues |
|-----|------------|---------------------|-----------------|
| 1   | <a href="https://soleng.jfrog.io/ui/scans-list/builds-scans/gh-ejs-demo/scan-descendants/93?version=93&package_id=build%3A%2F%2F%5Bdro-build-info%5D%2Fgh-ejs-demo&build_repository=dro-build-info&component_id=build%253A%252F%252F%255Bdro-build-info%255D%252Fgh-ejs-demo%253A93" target="_blank">Multi build 63</a> | <pre>No Watch is defined</pre> | <pre>Security Vulnerabilities: <b>4</b> <br>└── 4 SCA 🔴 <span style="color:red">4 High</span></pre> |

</details>

<u>Notes: </u>

1.  JFrog Security Scanner exported the Security {violations/issues} to **GitHub (🐙) Security Dashboard**.
2.  On the **JFrog Platform (🐸)**, the retention time for on-demand reports is 7 days.
3.  On the **JFrog Platform (🐸)**, the retention time for Build reports is {ZZZ} days.

<details open>

<h3>Curation Audit Results</h3>

| Audit Summary | Project name| Audit details |
|--------|----|---------|
| ❌ Failed  | github.com/jfrog/jfrog-cli | <pre>Total number of resolved packages: <b>139</b><br>🟢 Number of approved packages: <b>63</b><br>🔴 Number of blocked packages: <b>76</b><br>├── Violated policy: aged-asafa, Condition: Package version is aged (newer version available) (40)<br>└── Violated policy: MIT, Condition: MIT (44)</pre> |
| ✅ Passed | requirementsproject | <pre>Total number of resolved packages: <b>5</b><br>🟢 Number of approved packages: <b>0</b><br>🔴 Number of blocked packages: <b>5</b><br>├── Violated policy: testabc, Condition: CVE with CVSS score of 9 or above (fix version available) (1)<br>├── Violated policy: test, Condition: CVE with CVSS score of 9 or above (fix version available) (1)<br>├── Violated policy: aged-asafa, Condition: Package version is aged (newer version available) (3)<br>└── Violated policy: MIT, Condition: MIT (4)</pre> | 

</details>

</details>