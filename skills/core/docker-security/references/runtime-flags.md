# Runtime Flags

Every `docker run` flag that changes the security posture of a container, what it does, and what it
costs. Checked against the Docker CLI and security documentation on 2026-07-28:

- <https://docs.docker.com/reference/cli/docker/container/run/>
- <https://docs.docker.com/engine/security/>
- <https://docs.docker.com/engine/security/seccomp/>
- <https://docs.docker.com/engine/security/apparmor/>
- <https://docs.docker.com/engine/security/userns-remap/>
- <https://docs.docker.com/engine/security/rootless/>

Verify flags against your installed version. `docker run --help` is authoritative for your build.

## The hardened default

Start here and remove only what the container proves it needs.

```bash
docker run -d \
  --name api \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --memory=512m --memory-swap=512m \
  --cpus=1.0 \
  --pids-limit=200 \
  --restart=on-failure:5 \
  -p 127.0.0.1:8080:8080 \
  --network=app_net \
  registry.example.com/api@sha256:aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888
```

Nothing in that line is exotic. Every flag maps to a CIS section 5 control listed in
[cis-docker-benchmark.md](cis-docker-benchmark.md).

## Identity

| Flag | Effect | Cost |
|---|---|---|
| `--user UID:GID` | Runs as that UID regardless of the image's `USER` | Volume file ownership must match. Numeric only - a name must exist in the image's `/etc/passwd` |
| `--userns=host` | Disables user namespace remapping for this container | CIS 5.31. Removes the last layer between container root and host root |
| `--group-add` | Extra supplementary groups | Adding `docker` here is the socket problem by another route |

Prefer `--user` with numeric IDs even when the image sets `USER`. It is explicit at the call site
and survives a base image change.

## Filesystem

| Flag | Effect | Cost |
|---|---|---|
| `--read-only` | Root filesystem mounted read-only | Anything that writes needs an explicit tmpfs or volume. Finding all of them is the work |
| `--tmpfs /tmp:rw,noexec,nosuid,size=64m` | Writable in-memory scratch, size-capped | Counts against container memory. Without `size=` it can consume host memory |
| `-v host:container:ro` | Read-only bind mount | `ro` does not apply to a socket in any useful sense |
| `--mount type=bind,...,readonly` | Same, explicit syntax, fails on a missing source | More typing; fails loudly instead of creating a directory |

Never bind mount `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/lib/docker`, `/var/run/docker.sock`, or
the host's SSH directory. CIS 5.6. A writable mount of `/etc` is a path to host root via
`/etc/cron.d` or `/etc/sudoers.d`; a read-only mount of `/etc` still leaks `/etc/shadow`.

`:shared` mount propagation (CIS 5.20) lets the container's mounts appear on the host. Default
`private` is what you want.

## Capabilities

`--cap-drop=ALL` then add back individually. Docker's default set already excludes `SYS_ADMIN` and
`SYS_PTRACE`, but it includes several that matter.

| Capability | Kept by default | Why you might need it back |
|---|---|---|
| `CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `FSETID` | yes | Entrypoints that `chown` a volume before dropping privilege |
| `SETUID`, `SETGID` | yes | Any process that drops privilege itself (`su-exec`, `gosu`, nginx master) |
| `NET_BIND_SERVICE` | yes | Binding a port below 1024. Better answer: listen on 8080 and map it |
| `KILL` | yes | Signalling other processes in the container |
| `NET_RAW` | yes | `ping`, raw sockets. Also enables ARP spoofing on a shared bridge. Drop it |
| `SYS_ADMIN` | no | Mounting, some FUSE workloads. Close to root. Justify in writing |
| `SYS_PTRACE` | no | Debuggers and profilers. Add for a debug run, not in production |
| `SYS_MODULE` | no | Loading kernel modules. This is host compromise by design. Never |

`--privileged` is not "all capabilities". It also disables seccomp and AppArmor, allows all devices,
and remounts `/sys` writable. It is a different category of thing. CIS 5.5.

## Privilege escalation

| Flag | Effect |
|---|---|
| `--security-opt=no-new-privileges:true` | Sets `PR_SET_NO_NEW_PRIVS`. setuid binaries in the image cannot raise privilege |
| daemon `"no-new-privileges": true` | Same, for every container. CIS 2.14. Set it here, not per-run |

Complementary control: `RUN find / -perm /6000 -type f -exec chmod a-s {} +` in the build strips
setuid bits so there is nothing to exploit even if the flag is missed. CIS 4.8.

## Seccomp and AppArmor

| Flag | Effect | Cost |
|---|---|---|
| default (no flag) | Docker's default seccomp profile applies | Free. Do not turn it off |
| `--security-opt seccomp=unconfined` | Disables syscall filtering. CIS 5.22 | Every syscall reachable. Only for diagnosing a syscall-blocked failure |
| `--security-opt seccomp=./profile.json` | Custom profile | Maintenance. A libc or runtime upgrade changes the syscall set and breaks it |
| `--security-opt apparmor=docker-default` | Default AppArmor profile, Debian/Ubuntu. CIS 5.2 | Free |
| `--security-opt apparmor=my-profile` | Custom profile | Must be loaded on every host before the container starts |
| `--security-opt label=type:my_container.process` | SELinux, RHEL family. CIS 5.3 | Relabelling volumes (`:z`, `:Z`) |

Order of effort that actually pays: keep the default seccomp profile, keep the default AppArmor
profile, drop capabilities, and only then consider a custom profile. A hand-written seccomp profile
that is silently disabled by a typo in the path is worse than the default, because it looks done.

To build a real profile, record syscalls under load first - `strace -f -c`, `perf trace`, or
`oci-seccomp-bpf-hook` on Podman - then allowlist. Guessing produces a profile that fails in
production at 3am.

## Resources as a DoS control

| Flag | Effect | Missing it means |
|---|---|---|
| `--memory=512m` | Hard memory cap, OOM-kills the container. CIS 5.11 | One container's leak evicts every other container on the host |
| `--memory-swap=512m` | Equal to `--memory` disables swap for the container | Swap thrashing degrades the whole host |
| `--cpus=1.0` | CPU quota. CIS 5.12 | A busy loop starves neighbours |
| `--pids-limit=200` | Max processes. CIS 5.29 | A fork bomb exhausts the host PID table. This one is cheap and skipped constantly |
| `--ulimit nofile=1024:2048` | File descriptor cap. CIS 5.19 | FD exhaustion |
| `--restart=on-failure:5` | Bounded restarts. CIS 5.15 | A crash-looping container burns CPU and floods logs indefinitely |
| `--read-only` + sized tmpfs | Bounds disk and memory growth | Log growth fills the host disk |

Resource limits are availability controls with real security value. An attacker who cannot read your
data but can take the host down has still succeeded.

## Network

| Flag | Effect |
|---|---|
| `-p 127.0.0.1:8080:8080` | Bind to loopback only. CIS 5.14 |
| `-p 8080:8080` | Binds `0.0.0.0`. Reachable from the network, and it bypasses host firewall rules on Linux because Docker writes its own iptables chain |
| `--network=host` | No network namespace. CIS 5.10. Container sees all host interfaces, `EXPOSE` and `-p` stop applying, loopback-only services on the host become reachable |
| `--network=app_net` | User-defined bridge. CIS 5.30. Gives DNS by service name and does not put every container on one flat network |
| `--network=none` | No networking. The right answer for batch jobs that only touch a volume |
| `--pid=host` | Host process namespace. CIS 5.16. Container sees and can signal host processes, and reads their `/proc/*/environ` |
| `--ipc=host` | Host IPC namespace. CIS 5.17 |
| `--uts=host` | Host UTS namespace. CIS 5.21 |

The published-port firewall surprise is worth stating plainly: on Linux, `-p 8080:8080` inserts a
DNAT rule into the `DOCKER` chain, which is traversed before most `ufw` or `firewalld` INPUT rules.
People believe a host firewall is protecting a published port when it is not. Bind to `127.0.0.1`
and put a reverse proxy in front.

## Secrets at runtime

| Method | Verdict |
|---|---|
| `-e SECRET=...` | No. Visible in `docker inspect`, in `/proc/1/environ`, in child processes, and in crash dumps |
| `--env-file secrets.env` | Same exposure once loaded. Keeps it out of shell history, nothing more |
| `-v /run/secrets/x:/run/secrets/x:ro` | Acceptable. File permissions apply, not in `inspect` output |
| `--tmpfs /run/secrets` plus an injector writing into it | Better. Never touches disk |
| Swarm `docker secret` | Good. Mounted at `/run/secrets/<name>`, tmpfs-backed |
| Compose `secrets:` from `file:` | Better than `ENV`, but Docker Compose bind-mounts the host source file; not automatically tmpfs-backed |
| Agent-injected (Vault Agent, cloud secret CSI) | Best. Supports rotation without a rebuild |

Check with `docker inspect <container> --format '{{json .Config.Env}}'`. Anyone with daemon access
sees that, and so does any log or monitoring agent that scrapes container metadata.

## Rootless and Podman

| Option | What it changes | What it costs |
|---|---|---|
| Rootless Docker | Daemon and containers run as your UID. A container escape lands as an unprivileged user. CIS 2.1 | No ports below 1024 without `net.ipv4.ip_unprivileged_port_start`, slower networking via slirp4netns/pasta, some storage drivers unavailable, cgroup v2 required for limits |
| userns-remap | Rooted daemon, but container root maps to a high unprivileged host UID | Volume ownership shifts to the mapped range. Existing volumes need `chown`. CIS 2.9 |
| Podman rootless | No daemon at all, fork/exec model, same CLI surface | Compose support via `podman-compose` or the Docker-compatible socket. Some Docker-specific tooling assumes a daemon |

Rootless is the single largest reduction in blast radius available, and the reason it is not
universal is the port and networking friction, not any security argument.

## Flags that end the review

If any of these are present, that is the finding. Everything else is secondary.

```text
-v /var/run/docker.sock:/var/run/docker.sock    root on the host. CIS 5.32
--privileged                                    CIS 5.5
--pid=host                                      CIS 5.16
--network=host                                  CIS 5.10
--userns=host                                   CIS 5.31
--cap-add=SYS_ADMIN                             near-root
--cap-add=SYS_MODULE                            host kernel
--security-opt seccomp=unconfined               CIS 5.22
-v /:/host                                      CIS 5.6
-v /etc:/etc                                    CIS 5.6
--device=/dev/mem                               direct host memory. CIS 5.18
```
