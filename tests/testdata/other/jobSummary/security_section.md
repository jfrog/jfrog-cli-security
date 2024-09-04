
<details open><summary><h3>🔒 Curation Audit</h3></summary>

| Audit Summary | Project name | Audit Details |
|--------|--------|---------|
| <img alt="failed.svg" src=https://raw.githubusercontent.com/jfrog/jfrog-cli-security/main/resources/statusIcons/failed.svg> | /application1 | <pre>Total Number of resolved packages: <b>6</b><br>🟢 Approved packages: <b>3</b><br>🔴 Blocked packages: <b>3</b><details><summary><b>Violated Policy:</b> cvss_score, <b>Condition:</b> cvss score higher than 4.0 (<b>2</b>)</summary>📦 npm://test:2.0.0<br>📦 npm://underscore:1.0.0</details><details><summary><b>Violated Policy:</b> Malicious, <b>Condition:</b> Malicious package (<b>1</b>)</summary>📦 npm://lodash:1.0.0</details></pre> |
| <img alt="passed.svg" src=https://raw.githubusercontent.com/jfrog/jfrog-cli-security/main/resources/statusIcons/passed.svg> | /application2 | <pre>Total Number of resolved packages: <b>3</b></pre> |
| <img alt="failed.svg" src=https://raw.githubusercontent.com/jfrog/jfrog-cli-security/main/resources/statusIcons/failed.svg> | /application3 | <pre>Total Number of resolved packages: <b>5</b><br>🟢 Approved packages: <b>4</b><br>🔴 Blocked packages: <b>1</b><details><summary><b>Violated Policy:</b> Aged, <b>Condition:</b> Package is aged (<b>1</b>)</summary>📦 npm://test:1.0.0</details></pre> |
</details>