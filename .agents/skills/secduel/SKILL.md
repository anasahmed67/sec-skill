---
name: secduel
description: "Orchestrates an autonomous Red Team vs. Blue Team security duel using Antigravity's native multi-agent Swarm engine. Also triggered by the /secduel slash command."
metadata:
  icon: sports_kabaddi
---

# /secduel: Autonomous Red Team vs. Blue Team Multi-Agent Swarm Duel

Orchestrates an adversarial security duel inside Antigravity using native swarms. Two specialized sub-agents collaborate on the shared message board under coordinator supervision to stress-test and harden the codebase until it is verified impenetrable.

```
                  ┌──────────────────────┐
                  │ Coordinator Agent    │ (Referee & Compliance Judge)
                  └──────────┬───────────┘
                             │
            ┌────────────────┴────────────────┐
            ▼                                 ▼
   ┌─────────────────┐               ┌─────────────────┐
   │ Red Team Worker │               │ Blue Team Worker│
   │ (Attacker)      │ ──Messages──> │ (Defender)      │
   ├─────────────────┤               ├─────────────────┤
   │ Probes routes,  │               │ Generates fixes,│
   │ Crafts payloads,│               │ Verifies patch, │
   │ Finds bypasses  │               │ Closes leaks    │
   └─────────────────┘               └─────────────────┘
```

## Swarm Roles & Responsibilities

| Agent | Roster Name | Core Responsibility |
| :--- | :--- | :--- |
| **Coordinator** | Self | Referees the duel, initializes the swarm, evaluates progress, and issues the final OWASP / NIST SP 800-218 scorecard. |
| **Red Team** | `red-team` | Adversarial attacker. Scans code, studies AST data flows, identifies unconstrained sinks, and crafts exploit scenarios / filter bypasses. |
| **Blue Team** | `blue-team` | Defensive engineer. Implements parameterization, RBAC checks, and cryptographic mitigations; verifies fixes via `secskill_verify_patch`. |

---

## Duel Orchestration Procedure

### Phase 1: Initialize the Swarm
1. Identify the target path, file, or scenario (default: current workspace `.`).
2. Title the swarm:
   ```
   swarm{action: "title", title: "SecSkill Red vs. Blue Swarm: <target>"}
   ```

### Phase 2: Deploy Red Team Worker
Spawn the Red Team attacker on the shared message board:
```
swarm{
  action: "add",
  name: "red-team",
  brief: "You are the Red Team Attacker in an adversarial duel. Your goal: probe the target codebase (<target>), trace AST data flows from untrusted inputs to sensitive sinks (SQL, shell, eval, templates, file systems, IDOR), and identify bypasses of naive sanitizers. For every flaw you discover, post a message on the board tagging @blue-team detailing: 1) Target file and line number, 2) Vulnerability category (CWE/OWASP), 3) Attack vector and payload mechanism, 4) Why naive regex/blacklist defenses fail. Post [done] when your attack phase is concluded."
}
```

### Phase 3: Deploy Blue Team Worker
Spawn the Blue Team defender on the shared message board:
```
swarm{
  action: "add",
  name: "blue-team",
  brief: "You are the Blue Team Defender in an adversarial duel. Your goal: monitor the message board for attack vectors posted by @red-team. For each finding, develop an impenetrable defense-in-depth remediation: 1) Use driver-level parameterization (no SQL concatenation), 2) Use discrete argument lists with shell=False (no os.system), 3) Use CSPRNG secrets and Argon2/bcrypt, 4) Enforce tenant/ownership checks. Test your candidate patch using secskill_verify_patch to ensure zero regressions. When verified, apply the fix to the file and post a message tagging @coordinator with the hardened diff and proof of verification."
}
```

### Phase 4: Monitor, Referee, and Certify
1. The Coordinator monitors the message board using `read_board` and `swarm_wait`.
2. As `blue-team` applies verified patches, the Coordinator executes `secskill_scan` on patched files to certify vulnerability elimination.
3. Once all findings are neutralized and verified:
   - Terminate worker agents:
     ```
     swarm{action: "kill", name: "red-team"}
     swarm{action: "kill", name: "blue-team"}
     ```
   - Compile and output the **Certified Compliance Report**:
     - Vulnerabilities tested and mitigated (CWE Top 25, OWASP Top 10)
     - Initial CVSS score vs Final CVSS score (0.0)
     - Patched files list and verification status
     - NIST SP 800-218 (SSDF) compliance certificate

