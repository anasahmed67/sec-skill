"""Autonomous AI Red Team vs. Blue Team Duel Arena Orchestrator and Terminal Visualizer."""
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax
from rich.columns import Columns

from secskill.duel.models import (
    DuelRole,
    AttackPayload,
    DefensePatch,
    ValidationVerdict,
    DuelRound,
    DuelResult,
)
from secskill.duel.validator import DuelValidator
from secskill.duel.red_agent import RedTeamAgent
from secskill.duel.blue_agent import BlueTeamAgent

DEFAULT_SCENARIOS: Dict[str, Dict[str, str]] = {
    "sqli": {
        "title": "SQL Injection (CWE-89)",
        "vuln_type": "sqli",
        "code": (
            "def authenticate_user(user_input, password):\n"
            "    # Vulnerable f-string query construction directly interpolating user input\n"
            "    query = f\"SELECT * FROM users WHERE username = '{user_input}' AND pass = '{password}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        ),
    },
    "cmdi": {
        "title": "OS Command Injection (CWE-78)",
        "vuln_type": "cmdi",
        "code": (
            "import os\n"
            "def ping_server(hostname):\n"
            "    # Vulnerable os.system executing shell command with unsanitized host\n"
            "    cmd = f\"ping -c 1 {hostname}\"\n"
            "    return os.system(cmd)\n"
        ),
    },
    "path-traversal": {
        "title": "Path Traversal (CWE-22)",
        "vuln_type": "path-traversal",
        "code": (
            "def fetch_document(filename):\n"
            "    # Vulnerable open call without canonical resolution\n"
            "    path = f\"/var/www/uploads/{filename}\"\n"
            "    with open(path, 'r') as f:\n"
            "        return f.read()\n"
        ),
    },
    "xss": {
        "title": "Cross-Site Scripting (CWE-79)",
        "vuln_type": "xss",
        "code": (
            "def render_dashboard(user_name):\n"
            "    # Vulnerable HTML template reflection without context-aware escaping\n"
            "    html = f\"<div class='profile'>Welcome, {user_name}!</div>\"\n"
            "    return html\n"
        ),
    },
}


class DuelArena:
    """The Duel Arena where Red Team (Attacker) and Blue Team (Defender) battle in the terminal."""

    def __init__(
        self,
        target: Optional[str] = None,
        vuln_type: Optional[str] = None,
        red_model: str = "codellama",
        blue_model: str = "codellama",
        provider: str = "auto",
        max_rounds: int = 4,
        output_path: Optional[Path] = None,
        auto_apply: bool = False,
        turn_delay: float = 1.0,
        console: Optional[Console] = None,
    ):
        self.target = target
        self.vuln_type = vuln_type or "sqli"
        self.red_model = red_model
        self.blue_model = blue_model
        self.provider = provider
        self.max_rounds = max(1, max_rounds)
        self.output_path = output_path
        self.auto_apply = auto_apply
        self.turn_delay = turn_delay
        self.console = console or Console()

        # Agents
        self.red_agent = RedTeamAgent(model_name=red_model, provider_name=provider)
        self.blue_agent = BlueTeamAgent(model_name=blue_model, provider_name=provider)

        # Health Points
        self.red_hp = 100
        self.blue_hp = 100

        # Code state
        self.initial_code, self.target_title, self.source_file = self._resolve_target()
        self.current_code = self.initial_code

    def _resolve_target(self) -> tuple[str, str, Optional[Path]]:
        """Resolve input target to source code, title, and optional file path."""
        if not self.target or self.target.strip() == "":
            sc = DEFAULT_SCENARIOS["sqli"]
            return sc["code"], sc["title"], None

        # Check if target matches scenario name
        target_lower = self.target.lower().strip()
        for key, sc in DEFAULT_SCENARIOS.items():
            if target_lower in [key, key.replace("-", ""), sc["vuln_type"]]:
                self.vuln_type = sc["vuln_type"]
                return sc["code"], sc["title"], None

        # Check if target is a file path on disk
        target_path = Path(self.target)
        if target_path.is_file():
            try:
                code = target_path.read_text(encoding="utf-8")
                # Infer vulnerability type
                inferred_type = self._infer_vuln_type(code)
                self.vuln_type = inferred_type
                return code, f"File: {target_path.name} ({inferred_type.upper()})", target_path
            except Exception:
                pass

        # Treat target as raw code snippet
        inferred_type = self._infer_vuln_type(self.target)
        self.vuln_type = inferred_type
        return self.target, f"Snippet ({inferred_type.upper()})", None

    def _infer_vuln_type(self, code: str) -> str:
        code_lower = code.lower()
        if "cursor.execute" in code_lower or "select " in code_lower:
            return "sqli"
        elif "os.system" in code_lower or "subprocess" in code_lower:
            return "cmdi"
        elif "open(" in code_lower and ("filename" in code_lower or "path" in code_lower):
            return "path-traversal"
        elif "html" in code_lower or "render" in code_lower or "<div" in code_lower:
            return "xss"
        return "sqli"

    def render_health_bars(self) -> Panel:
        """Render side-by-side terminal HUD health bars for Red Team and Blue Team."""
        # Calculate bar filled slots (out of 20)
        red_slots = max(0, min(20, int((self.red_hp / 100.0) * 20)))
        blue_slots = max(0, min(20, int((self.blue_hp / 100.0) * 20)))

        # Color schemes based on HP
        red_color = "red" if self.red_hp > 30 else "bold red blink"
        blue_color = "bright_cyan" if self.blue_hp > 30 else "bold yellow"

        red_bar_str = "█" * red_slots + "░" * (20 - red_slots)
        blue_bar_str = "█" * blue_slots + "░" * (20 - blue_slots)

        red_hud = (
            f"[bold red]🔴 RED TEAM (Attacker)[/bold red]\n"
            f"[dim]Model: {self.red_model}[/dim]\n"
            f"HP: [{red_color}]{self.red_hp:>3}/100[/{red_color}] [{red_color}][{red_bar_str}][/{red_color}]"
        )
        blue_hud = (
            f"[bold bright_cyan]🔵 BLUE TEAM (Defender)[/bold bright_cyan]\n"
            f"[dim]Model: {self.blue_model}[/dim]\n"
            f"HP: [{blue_color}]{self.blue_hp:>3}/100[/{blue_color}] [{blue_color}][{blue_bar_str}][/{blue_color}]"
        )

        grid = Table.grid(expand=True)
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(red_hud, blue_hud)

        return Panel(
            grid,
            title="[bold yellow]⚔️  DUEL ARENA COMBAT STATUS  ⚔️[/bold yellow]",
            border_style="yellow",
        )

    def run(self) -> DuelResult:
        """Execute the turn-by-turn duel between Red and Blue agents."""
        start_time = time.time()
        rounds_data: List[DuelRound] = []

        # Print Arena Banner
        self.console.print("\n" + "=" * 80, style="bold cyan")
        self.console.print("⚔️   SECSKILL AUTONOMOUS AI RED TEAM VS. BLUE TEAM DUEL ARENA   ⚔️", style="bold yellow", justify="center")
        self.console.print("Two local LLMs battle in the terminal until the code is impenetrable", style="italic white", justify="center")
        self.console.print("=" * 80 + "\n", style="bold cyan")

        self.console.print(f"[bold white]Target Arena Subject:[/bold white] [cyan]{self.target_title}[/cyan]")
        self.console.print(f"[bold white]Vulnerability Vector:[/bold white] [magenta]{self.vuln_type.upper()}[/magenta]")
        self.console.print(f"[bold white]Max Engagement Rounds:[/bold white] [yellow]{self.max_rounds}[/yellow]\n")

        # Initial code preview
        self.console.print(Panel(
            Syntax(self.initial_code.strip(), "python", theme="monokai", line_numbers=True),
            title="[bold red]Initial Target Code (Vulnerable)[/bold red]",
            border_style="red"
        ))

        referee_feedback = "Initial scan: Vulnerable construct detected."

        # Main Battle Loop
        for round_idx in range(1, self.max_rounds + 1):
            if self.red_hp <= 0 or self.blue_hp <= 0:
                break

            round_title = f"ROUND {round_idx} / {self.max_rounds}"
            self.console.print(f"\n[bold yellow]{'━' * 30} [ {round_title} ] {'━' * 30}[/bold yellow]\n")

            # 1. Render Health HUD
            self.console.print(self.render_health_bars())
            if self.turn_delay > 0:
                time.sleep(self.turn_delay * 0.5)

            # 2. Red Team Attack Phase
            self.console.print(f"[bold red]⚡ Red Team is inspecting code and crafting exploit...[/bold red]")
            red_payload = self.red_agent.craft_exploit(
                code=self.current_code,
                vuln_type=self.vuln_type,
                round_number=round_idx,
                referee_feedback=referee_feedback,
            )

            red_panel_text = (
                f"[bold red]Payload Name:[/bold red] {red_payload.name}\n"
                f"[bold red]Attack Vector:[/bold red] {red_payload.vector}\n"
                f"[bold red]Bypass Technique:[/bold red] {red_payload.bypass_technique}\n"
                f"[bold red]Payload String:[/bold red] [bold yellow]\"{red_payload.payload}\"[/bold yellow]\n\n"
                f"[dim]{red_payload.explanation}[/dim]"
            )
            self.console.print(Panel(
                red_panel_text,
                title=f"[bold red]🔴 RED TEAM ATTACK [Round {round_idx}][/bold red]",
                border_style="red"
            ))

            if self.turn_delay > 0:
                time.sleep(self.turn_delay)

            # 3. SecSkill Referee Validation on Red's Move
            verdict_before = DuelValidator.validate(
                code=self.current_code,
                vuln_type=self.vuln_type,
                payload=red_payload,
            )

            blue_damage = 0
            if verdict_before.bypass_detected:
                blue_damage = 40 if round_idx == 1 else 30
                self.blue_hp = max(0, self.blue_hp - blue_damage)
                ref_status = f"[bold red]💥 BYPASS CONFIRMED! Exploit Breaches Defense! Blue takes -{blue_damage} HP![/bold red]"
            else:
                ref_status = "[bold green]🛡️ BLOCKED! Current defense held against payload.[/bold green]"

            referee_content = (
                f"{ref_status}\n\n"
                f"• [bold]AST Violations:[/bold] {len(verdict_before.ast_violations)} issue(s)\n"
                f"• [bold]Taint Flow:[/bold] {'UNRESTRICTED SINK' if not verdict_before.taint_clean else 'Neutralized'}\n"
                f"• [bold]Referee Verdict:[/bold] {verdict_before.details}"
            )
            self.console.print(Panel(
                referee_content,
                title="[bold yellow]⚡ SECSKILL AST & TAINT REFEREE[/bold yellow]",
                border_style="yellow"
            ))

            if self.turn_delay > 0:
                time.sleep(self.turn_delay)

            # 4. Blue Team Defense Phase
            self.console.print(f"[bold cyan]🛡️  Blue Team is analyzing AST feedback and generating patch...[/bold cyan]")
            blue_patch = self.blue_agent.create_patch(
                original_code=self.current_code,
                vuln_type=self.vuln_type,
                round_number=round_idx,
                total_rounds=self.max_rounds,
                red_payload=red_payload,
                referee_feedback=verdict_before.feedback_for_blue,
            )

            # Update current code to blue's patch
            self.current_code = blue_patch.code

            blue_panel_text = (
                f"[bold cyan]Defense Strategy:[/bold cyan] {blue_patch.strategy}\n"
                f"[bold cyan]Architecture Rationale:[/bold cyan] {blue_patch.explanation}\n\n"
                f"[bold cyan]Hardened Code Snapshot:[/bold cyan]"
            )
            self.console.print(Panel(
                Syntax(blue_patch.code.strip(), "python", theme="monokai", line_numbers=True),
                title=f"[bold bright_cyan]🔵 BLUE TEAM DEFENSE PATCH [Round {round_idx}][/bold bright_cyan]",
                border_style="cyan"
            ))

            if self.turn_delay > 0:
                time.sleep(self.turn_delay)

            # 5. SecSkill Re-Evaluation of Blue's Patch
            verdict_after = DuelValidator.validate(
                code=self.current_code,
                vuln_type=self.vuln_type,
                payload=red_payload,
            )

            red_damage = 0
            if verdict_after.is_safe:
                red_damage = 50
                self.red_hp = max(0, self.red_hp - red_damage)
                counter_msg = f"[bold green]🛡️ SHIELD COUNTER-ATTACK! AST Verified Impenetrable! Red takes -{red_damage} HP![/bold green]"
            else:
                counter_msg = "[bold yellow]⚠️ Patch improved security, but AST violations remain under scrutiny.[/bold yellow]"

            self.console.print(Panel(
                f"{counter_msg}\n\n"
                f"• [bold]AST Integrity:[/bold] {'SAFE' if verdict_after.ast_safe else 'VIOLATIONS PERSIST'}\n"
                f"• [bold]Taint Cleanliness:[/bold] {'ZERO TAINT REACHES SINK' if verdict_after.taint_clean else 'TAINT FLOW ACTIVE'}\n"
                f"• [bold]Status:[/bold] {verdict_after.feedback_for_blue}",
                title="[bold green]⚡ SECSKILL POST-PATCH VERIFICATION[/bold green]",
                border_style="green"
            ))

            referee_feedback = verdict_after.feedback_for_blue

            # Record Round
            rounds_data.append(
                DuelRound(
                    round_number=round_idx,
                    red_payload=red_payload,
                    validation_before=verdict_before,
                    blue_patch=blue_patch,
                    validation_after=verdict_after,
                    red_damage=red_damage,
                    blue_damage=blue_damage,
                    red_hp=self.red_hp,
                    blue_hp=self.blue_hp,
                    narrative=[ref_status, counter_msg],
                )
            )

            # Check for victory conditions
            if self.red_hp <= 0:
                break

        # Final Outcome Determination
        is_hardened = (self.red_hp <= 0 or (rounds_data and rounds_data[-1].validation_after and rounds_data[-1].validation_after.is_safe))
        winner = "BLUE" if is_hardened else ("RED" if self.blue_hp <= 0 else "DRAW")
        duration = round(time.time() - start_time, 2)

        # Render Final Health Bars & Victory Banner
        self.console.print("\n" + "=" * 80, style="bold yellow")
        self.console.print(self.render_health_bars())

        saved_path_str: Optional[str] = None

        if winner == "BLUE":
            self.console.print(Panel(
                "[bold green]🏆  VICTORY: BLUE TEAM TRIUMPHS!  🏆[/bold green]\n\n"
                "[bold white]The code has survived all adversarial attacks and is certified impenetrable by SecSkill AST & Taint rules![/bold white]\n"
                f"Total Rounds: [yellow]{len(rounds_data)}[/yellow] | Combat Duration: [yellow]{duration}s[/yellow]",
                title="[bold green]DUEL DECISION: CODE HARDENED[/bold green]",
                border_style="bold green"
            ))

            # Save the hardened code
            saved_path_str = self._save_hardened_code(self.current_code)

        elif winner == "RED":
            self.console.print(Panel(
                "[bold red]💀  BREACH: RED TEAM CRACKS DEFENSE!  💀[/bold red]\n\n"
                "[bold white]Defender's patches were bypassed. Vulnerability vectors remain exploitable.[/bold white]\n"
                f"Total Rounds: [yellow]{len(rounds_data)}[/yellow] | Combat Duration: [yellow]{duration}s[/yellow]",
                title="[bold red]DUEL DECISION: VULNERABILITY PERSISTS[/bold red]",
                border_style="bold red"
            ))
        else:
            self.console.print(Panel(
                "[bold yellow]⚖️  DRAW: COMBAT TIME EXPIRED  ⚖️[/bold yellow]\n\n"
                "Both agents sustained damage. Final code state requires further refinement.",
                title="[bold yellow]DUEL DECISION: STALEMATE[/bold yellow]",
                border_style="bold yellow"
            ))

        # Combat Summary Table
        summary_table = Table(title="⚔️ SecSkill Duel Arena Combat Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Round", style="cyan", width=8)
        summary_table.add_column("Attacker Payload", style="red", width=25)
        summary_table.add_column("Bypass Vector", style="yellow", width=20)
        summary_table.add_column("Defender Counter", style="bright_cyan", width=25)
        summary_table.add_column("AST Result", style="green", width=12)

        for r in rounds_data:
            summary_table.add_row(
                f"Round {r.round_number}",
                r.red_payload.name,
                r.red_payload.bypass_technique[:20],
                r.blue_patch.strategy if r.blue_patch else "N/A",
                "IMPENETRABLE" if (r.validation_after and r.validation_after.is_safe) else "VULNERABLE",
            )
        self.console.print(summary_table)

        return DuelResult(
            winner=winner,
            target_name=self.target_title,
            vulnerability_type=self.vuln_type,
            rounds=rounds_data,
            initial_code=self.initial_code,
            final_code=self.current_code,
            is_hardened=is_hardened,
            saved_path=saved_path_str,
            total_rounds=len(rounds_data),
            duration_seconds=duration,
        )

    def _save_hardened_code(self, code: str) -> str:
        """Save hardened code to requested output path, or overwrite target file if auto_apply."""
        target_dest: Path

        if self.output_path:
            target_dest = Path(self.output_path)
        elif self.auto_apply and self.source_file:
            # Backup original file
            backup_file = self.source_file.with_suffix(self.source_file.suffix + ".bak")
            try:
                backup_file.write_text(self.source_file.read_text(encoding="utf-8"), encoding="utf-8")
                self.console.print(f"[dim]Original file backed up to: {backup_file}[/dim]")
            except Exception:
                pass
            target_dest = self.source_file
        elif self.source_file:
            # Save next to source file as <name>_hardened.py
            target_dest = self.source_file.parent / f"{self.source_file.stem}_hardened{self.source_file.suffix}"
        else:
            # Save in current directory as hardened_code.py
            target_dest = Path("./hardened_code.py")

        target_dest.parent.mkdir(parents=True, exist_ok=True)
        target_dest.write_text(code, encoding="utf-8")
        self.console.print(
            f"\n[bold green]✓ Verified hardened code saved successfully to:[/bold green] [cyan]{target_dest.resolve()}[/cyan]\n"
        )
        return str(target_dest.resolve())

