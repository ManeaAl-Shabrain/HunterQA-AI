"""Render non-secret Compose settings and a native unit from one validated spec."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re

FIELDS = {"schema_version", "workspace_id", "home", "runtime_prefix", "user", "uid", "gid", "port"}


def validate(data):
    if not isinstance(data, dict) or set(data) != FIELDS or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Invalid deployment configuration")
    if not isinstance(data["workspace_id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,47}", data["workspace_id"]):
        raise ValueError("Invalid workspace identifier")
    if not isinstance(data["user"], str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{1,30}", data["user"]) or data["user"] == "root":
        raise ValueError("Use a dedicated non-root Linux service account")
    for name in ("uid", "gid"):
        if type(data[name]) is not int or not 1000 <= data[name] <= 2_147_483_647:
            raise ValueError("Use explicit unprivileged UID/GID values")
    if type(data["port"]) is not int or not 1024 <= data["port"] <= 65535:
        raise ValueError("Choose an unprivileged loopback port")
    for name in ("home", "runtime_prefix"):
        value = data[name]
        if (not isinstance(value, str) or len(value) > 256 or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
                or PurePosixPath(value).as_posix() != value or ".." in PurePosixPath(value).parts
                or len(PurePosixPath(value).parts) < 3):
            raise ValueError("Use canonical Linux paths without shell/systemd expansion characters")
    home, prefix = PurePosixPath(data["home"]), PurePosixPath(data["runtime_prefix"])
    if home.is_relative_to(prefix) or prefix.is_relative_to(home):
        raise ValueError("Runtime code and private workspace must remain separate")
    return dict(data)


def render(data):
    data = validate(data)
    home, prefix, workspace_id = data["home"], data["runtime_prefix"], data["workspace_id"]
    env = {"HUNTERQA_HOME": home, "HUNTERQA_RUNTIME_PREFIX": prefix, "HUNTERQA_WORKSPACE_ID": workspace_id,
        "HUNTERQA_UID": str(data["uid"]), "HUNTERQA_GID": str(data["gid"]), "HUNTERQA_PORT": str(data["port"])}
    common = {"HUNTERQA_OPERATOR_ROOT": home + "/control", "HUNTERQA_WORKSPACE_CONFIG": home + "/control/" + workspace_id + "/workspace.json",
        "HUNTERQA_PORT": str(data["port"]), "HUNTERQA_RUNTIME_PREFIX": prefix, "HUNTERQA_HOME": home,
        "PLAYWRIGHT_BROWSERS_PATH": prefix + "/browsers", "HOME": home + "/runtime-home",
        "PATH": prefix + "/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    unit = ["[Unit]", "Description=HunterQA " + workspace_id + " workspace", "After=network.target", "", "[Service]", "Type=exec",
        "User=" + data["user"], "Group=" + str(data["gid"]), "UMask=0077", "WorkingDirectory=" + home]
    unit += ["Environment=" + key + "=" + value for key, value in common.items()]
    unit += [f"ExecStartPre={prefix}/bin/python -c 'import os; assert os.getuid() == {data['uid']} and os.getgid() == {data['gid']} and set(os.getgroups()) <= {{{data['gid']}}}'",
        f"ExecStart={prefix}/bin/hunterqa workspace-serve --require-auth-policy --config {common['HUNTERQA_WORKSPACE_CONFIG']} --port {data['port']}",
        f"ExecStartPost={prefix}/bin/python {prefix}/share/hunterqa/verify_deployment.py --phase health --wait 30",
        "Restart=on-failure", "RestartSec=5", "TimeoutStopSec=30", "KillMode=control-group", "NoNewPrivileges=yes",
        "PrivateTmp=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes", "ProtectKernelTunables=yes",
        "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "RestrictRealtime=yes", "LockPersonality=yes",
        "CapabilityBoundingSet=", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "ReadWritePaths=" + home,
        "MemoryMax=1G", "TasksMax=128", "CPUQuota=100%", "LimitNOFILE=4096", "", "[Install]", "WantedBy=multi-user.target", ""]
    return {"runtime.env": "\n".join(key + "=" + value for key, value in env.items()) + "\n",
        "hunterqa-" + workspace_id + ".service": "\n".join(unit)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    config = Path(args.config)
    if config.is_symlink() or not config.is_file() or config.stat().st_size > 8192:
        raise ValueError("Invalid bounded deployment specification")
    outputs = render(json.loads(config.read_text(encoding="utf-8")))
    directory = Path(args.out_dir)
    if (not directory.is_absolute() or not directory.is_dir() or any(directory.iterdir())
            or any(p.is_symlink() or (p / ".git").exists() for p in (directory, *directory.parents))
            or (os.name == "posix" and (directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.geteuid()))):
        raise ValueError("Choose an existing empty owner-private output directory outside Git")
    for name, value in outputs.items():
        fd = os.open(directory / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(value)
    print(json.dumps({"rendered": sorted(outputs), "secrets_included": False, "production_ready": False}))


if __name__ == "__main__":
    main()
