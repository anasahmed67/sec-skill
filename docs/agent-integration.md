# Agent Integration Guide

SecSkill is designed to be invoked by autonomous coding agents.
When an agent edits code, it can call the `SecSkillAgentSkill` entrypoint:

```python
from secskill.agent_skill import SecSkillAgentSkill

skill = SecSkillAgentSkill()
findings = skill.run_security_scan("src/auth.py")
```
