from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HardeningLayoutTest(unittest.TestCase):
    def test_inventory_is_parameterized(self) -> None:
        content = (ROOT / "hosts.yml").read_text(encoding="utf-8")
        self.assertIn("{{ target_vps_ip }}", content)
        self.assertNotRegex(content, r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def test_two_phase_playbooks_exist(self) -> None:
        self.assertTrue((ROOT / "bootstrap-playbook.yml").exists())
        self.assertTrue((ROOT / "lockdown-playbook.yml").exists())

    def test_secure_variable_template_exists(self) -> None:
        example = ROOT / "group_vars" / "all.example.yml"
        self.assertTrue(example.exists())
        content = example.read_text(encoding="utf-8")
        for key in (
            "target_vps_ip",
            "bootstrap_allowed_ip",
            "ssh_pubkey_path",
            "tailscale_authkey",
            "admin_user",
            "ssh_port",
        ):
            self.assertIn(f"{key}:", content)

    def test_firewall_role_mentions_tailscale_only_policy(self) -> None:
        content = (ROOT / "roles" / "firewall" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("tailscale0", content)
        self.assertIn("bootstrap_allowed_ip", content)
        self.assertIn("bootstrap_allowed_ip | length > 0", content)

    def test_firewall_role_has_fail_safe_reenable_path(self) -> None:
        content = (ROOT / "roles" / "firewall" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("block:", content)
        self.assertIn("rescue:", content)
        self.assertIn("always:", content)
        self.assertIn("ufw --force enable", content)

    def test_firewall_role_allows_traefik_ports(self) -> None:
        task_content = (ROOT / "roles" / "firewall" / "tasks" / "main.yml").read_text(encoding="utf-8")
        default_content = (ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
        example_content = (ROOT / "group_vars" / "all.example.yml").read_text(encoding="utf-8")
        self.assertIn("inbound_allowed_tcp_ports", task_content)
        self.assertIn("inbound_allowed_tcp_ports:", default_content)
        self.assertIn("- 80", default_content)
        self.assertIn("- 443", default_content)
        self.assertIn("inbound_allowed_tcp_ports:", example_content)

    def test_ssh_role_uses_drop_in_hardening_file(self) -> None:
        content = (ROOT / "roles" / "ssh" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("/etc/ssh/sshd_config.d", content)
        self.assertIn("00-ansible-hardening.conf", content)
        self.assertIn("Include /etc/ssh/sshd_config.d/*.conf", content)

    def test_tailscale_role_supports_join_and_reconcile_paths(self) -> None:
        content = (ROOT / "roles" / "tailscale" / "tasks" / "main.yml").read_text(encoding="utf-8")
        defaults = (ROOT / "roles" / "tailscale" / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("tailscale_preexisting_ipv4", content)
        self.assertIn("tailscale status --json", content)
        self.assertIn("tailscale_reauth_required", content)
        self.assertIn("tailscale logout", content)
        self.assertIn("Bring node into tailnet", content)
        self.assertIn("Reconcile tailscale settings", content)
        self.assertIn("no_log: true", content)
        self.assertIn("tailscale_force_reauth", defaults)
        self.assertIn("tailscale_expected_tailnet", defaults)

    def test_validation_role_exists(self) -> None:
        validation_role = ROOT / "roles" / "validation" / "tasks" / "main.yml"
        self.assertTrue(validation_role.exists())

    def test_readme_describes_two_phase_tailscale_flow(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("ubuntu 22.04", content)
        self.assertIn("two-phase", content)
        self.assertIn("tailscale", content)
        self.assertIn("bootstrap", content)
        self.assertIn("lockdown", content)

    def test_portfolio_runtime_role_exists(self) -> None:
        runtime_role = ROOT / "roles" / "portfolio_runtime" / "tasks" / "main.yml"
        self.assertTrue(runtime_role.exists())

    def test_bootstrap_includes_portfolio_runtime_role(self) -> None:
        content = (ROOT / "bootstrap-playbook.yml").read_text(encoding="utf-8")
        self.assertIn("- role: portfolio_runtime", content)

    def test_readme_documents_docker_runtime_install(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("docker", content)
        self.assertIn("docker compose", content)
        self.assertIn("python3-venv", content)

    def test_auth_mode_variables_are_documented(self) -> None:
        content = (ROOT / "group_vars" / "all.example.yml").read_text(encoding="utf-8")
        self.assertIn("bootstrap_auth_method:", content)
        self.assertIn("bootstrap_root_password:", content)
        self.assertIn("bootstrap_command_timeout_seconds:", content)

    def test_bootstrap_playbook_supports_password_fallback(self) -> None:
        content = (ROOT / "bootstrap-playbook.yml").read_text(encoding="utf-8")
        self.assertIn("bootstrap_auth_method", content)
        self.assertIn("ansible_connection: paramiko", content)

    def test_bootstrap_playbook_has_password_expiry_guard(self) -> None:
        content = (ROOT / "bootstrap-playbook.yml").read_text(encoding="utf-8")
        self.assertIn("gather_facts: false", content)
        self.assertIn("ansible.builtin.setup", content)
        self.assertIn("forced password rotation", content)
        self.assertIn("Failed to create temporary directory", content)

    def test_requirements_playbook_supports_password_fallback(self) -> None:
        content = (ROOT / "requirements-playbook.yml").read_text(encoding="utf-8")
        self.assertIn("bootstrap_auth_method", content)
        self.assertIn("ansible_connection: paramiko", content)

    def test_readme_mentions_password_bootstrap_flow(self) -> None:
        content = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("password fallback", content)
        self.assertIn("bootstrap_root_password", content)

    def test_main_playbook_orchestrates_tailnet_lockdown(self) -> None:
        content = (ROOT / "main-playbook.yml").read_text(encoding="utf-8")
        self.assertIn("add_host", content)
        self.assertIn("lockdown_targets", content)
        self.assertIn("hostvars[inventory_hostname].tailscale_ipv4.stdout", content)
        self.assertIn("tailscale_ipv4_endpoint", content)

    def test_tailscale_role_defines_hostname(self) -> None:
        content = (ROOT / "roles" / "tailscale" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("--hostname=", content)

    def test_group_vars_include_tailscale_hostname(self) -> None:
        example = (ROOT / "group_vars" / "all.example.yml").read_text(encoding="utf-8")
        defaults = (ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8")
        self.assertIn("tailscale_hostname: prod-vps", example)
        self.assertIn("tailscale_hostname: prod-vps", defaults)

    def test_tests_do_not_include_private_literals(self) -> None:
        forbidden_literals = [
            "BEGIN " + "OPENSSH PRIVATE KEY",
            "BEGIN " + "RSA PRIVATE KEY",
            "gh" + "p_",
            "sk" + "-live-",
            "ts" + "key-",
        ]
        email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        for test_file in (ROOT / "tests").glob("*.py"):
            content = test_file.read_text(encoding="utf-8")
            for literal in forbidden_literals:
                self.assertNotIn(literal, content, f"{test_file} contains sensitive literal: {literal}")
            for email in email_pattern.findall(content):
                self.assertTrue(email.endswith("@example.com"), f"{test_file} contains non-placeholder email: {email}")


if __name__ == "__main__":
    unittest.main()
