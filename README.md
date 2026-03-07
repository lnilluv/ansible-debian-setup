# Ubuntu 22.04 VPS Hardening with Ansible (Tailscale-only SSH)

This project hardens an Ubuntu 22.04 VPS from a macOS control host using a two-phase workflow.

## Security model

- Phase 1 (`bootstrap-playbook.yml`):
  - connect to VPS public IP,
  - allow SSH only from your current public IP (`bootstrap_allowed_ip`),
  - create admin user with SSH key,
  - install and join Tailscale.
- Phase 2 (`lockdown-playbook.yml`):
  - verify Tailscale connectivity,
  - remove public SSH allow rule,
  - keep SSH access only through `tailscale0` policy.

This means final SSH access is Tailscale-only.

Bootstrap supports key-first with password fallback. Set `bootstrap_auth_method` to:

- `auto` (default): use key when provided, and password fallback when provided.
- `key`: require SSH private key path only.
- `password`: require root password only.

## Requirements

- macOS host with Python 3 and Ansible installed.
- Target VPS running Ubuntu 22.04.
- Tailscale auth key (ephemeral recommended).
- Existing bootstrap SSH private key for initial login.

Install Ansible and required collection on macOS:

```bash
python3 -m pip install --user ansible
ansible-galaxy collection install ansible.posix
```

## Configuration

Base defaults live in `group_vars/all.yml`.

Firewall defaults are tuned to avoid Traefik breakage:

- incoming web ports `80` and `443` are allowed via `inbound_allowed_tcp_ports`,
- outbound default remains allow, with explicit outbound allow lists still configurable.

By default, bootstrap also installs portfolio runtime tooling:

- Docker Engine (`docker-ce`, `docker-ce-cli`, `containerd.io`)
- Docker plugins (`docker buildx`, `docker compose`)
- Dev tools (`git`, `make`, `jq`, `htop`, `tmux`, `python3-venv`, `python3-pip`)

Set `install_portfolio_runtime: false` to skip this layer.

Copy `group_vars/all.example.yml` values into runtime parameters. Do not commit secrets.

Required runtime values:

- `target_vps_ip`: public IP of the VPS.
- `bootstrap_allowed_ip`: your current public IP that can SSH during bootstrap.
- `ssh_pubkey_path`: path to your public key on macOS host.
- `bootstrap_auth_method`: `auto`, `key`, or `password`.
- `bootstrap_command_timeout_seconds`: timeout used for early bootstrap checks.
- `bootstrap_ssh_private_key_path`: private key path for initial SSH.
- `bootstrap_root_password`: root password for password fallback.
- `tailscale_hostname`: node name assigned during `tailscale up`.
- `tailscale_authkey`: auth key used by `tailscale up`.

## Usage

Recommended one-shot run (bootstrap + automatic switch to Tailscale endpoint + lockdown):

```bash
ansible-playbook -i hosts.yml main-playbook.yml \
  -e target_vps_ip="203.0.113.10" \
  -e bootstrap_allowed_ip="198.51.100.25" \
  -e bootstrap_auth_method="key" \
  -e ssh_pubkey_path="/Users/you/.ssh/id_ed25519.pub" \
  -e bootstrap_ssh_private_key_path="/Users/you/.ssh/id_ed25519" \
  -e tailscale_authkey="tskey-ephemeral-xxxxx"
```

`main-playbook.yml` reuses the Tailnet IPv4 discovered during bootstrap and uses that
host for the lockdown phase, avoiding endpoint-discovery stalls between phases.

Run bootstrap:

```bash
ansible-playbook -i hosts.yml bootstrap-playbook.yml \
  -e target_vps_ip="203.0.113.10" \
  -e bootstrap_allowed_ip="198.51.100.25" \
  -e bootstrap_auth_method="key" \
  -e ssh_pubkey_path="/Users/you/.ssh/id_ed25519.pub" \
  -e bootstrap_ssh_private_key_path="/Users/you/.ssh/id_ed25519" \
  -e tailscale_authkey="tskey-ephemeral-xxxxx"
```

Run bootstrap with password fallback:

```bash
ansible-playbook -i hosts.yml bootstrap-playbook.yml \
  -e target_vps_ip="203.0.113.10" \
  -e bootstrap_allowed_ip="198.51.100.25" \
  -e bootstrap_auth_method="password" \
  -e ssh_pubkey_path="/Users/you/.ssh/id_ed25519.pub" \
  -e bootstrap_root_password="your-root-password" \
  -e tailscale_authkey="tskey-ephemeral-xxxxx"
```

If provider images force an initial password rotation, the playbook now fails early with a clear message
instead of a generic temp-directory error. Complete one manual login/password change, then rerun bootstrap.

Run lockdown:

```bash
ansible-playbook -i hosts.yml lockdown-playbook.yml \
  -e target_vps_ip="203.0.113.10" \
  -e bootstrap_allowed_ip="198.51.100.25" \
  -e bootstrap_auth_method="key" \
  -e bootstrap_ssh_private_key_path="/Users/you/.ssh/id_ed25519"
```

Optional compatibility wrapper:

```bash
ansible-playbook -i hosts.yml main-playbook.yml -e ...
```

Verify runtime tooling on VPS:

```bash
docker --version
docker compose version
python3 -m venv --help
id {{ admin_user }}
```

## Recovery / rollback

If you lose Tailscale connectivity, use the VPS provider console to:

1. temporarily disable UFW (`ufw disable`) or add temporary public SSH allow rule,
2. restart `tailscaled` and verify `tailscale ip -4`,
3. rerun `lockdown-playbook.yml`.

## Notes

- `group_vars/all.vault.yml` is reserved for secrets via `ansible-vault`; pass it explicitly (for example `-e @group_vars/all.vault.yml`).
- `.gitignore` blocks local secret files and worktrees.
