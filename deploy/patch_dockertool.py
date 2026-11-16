"""Make Flowsint's Docker-based tool wrappers run installed binaries when one is available.

Upstream launches ProjectDiscovery tools (subfinder, dnsx, httpx, naabu, asnmap, mapcidr) as containers through the
Docker socket, which this deployment does not mount. Every wrapper calls DockerTool.launch(command, ...), and a few
also call self.client.containers.run(...) directly (for --version), so appending a local-execution path to
dockertool.py covers all of them. Without a local binary the original behaviour is untouched.
Fails the build loudly if upstream's DockerTool changes shape.
"""
import pathlib

p = pathlib.Path("/app/flowsint-enrichers/src/tools/dockertool.py")
s = p.read_text()
assert "class DockerTool(Tool):" in s, "upstream dockertool.py changed; review this patch"
for needle in ("def __init__(self, image: str", "def install(self)", "def is_installed(self)", "def version(self)", "def launch("):
    assert needle in s, f"upstream dockertool.py no longer has {needle}; review this patch"
assert "_local_binary" not in s, "already patched"

s += '''

# ---- appended by deploy/patch_dockertool.py: run an installed binary instead of a container ----
import os as _os
import shlex as _shlex
import shutil as _shutil
import subprocess as _subprocess


def _local_binary(image):
    """Binary for an image like projectdiscovery/httpx. /usr/local/bin first: the Python httpx CLI sits earlier on PATH."""
    name = image.split("/")[-1].split(":")[0]
    pinned = _os.path.join("/usr/local/bin", name)
    if _os.path.isfile(pinned) and _os.access(pinned, _os.X_OK):
        return pinned
    return None


def _argv(binary, command, entrypoint=None):
    args = _shlex.split(command) if isinstance(command, str) else [str(c) for c in command]
    return ([entrypoint] if entrypoint else [binary]) + args


class _LocalContainers:
    def __init__(self, binary):
        self._binary = binary

    def run(self, image=None, command="", **kwargs):
        p = _subprocess.run(_argv(self._binary, command, kwargs.get("entrypoint")), capture_output=True, timeout=120)
        return p.stdout + p.stderr


class _LocalImages:
    def get(self, *a, **k):
        return True

    def pull(self, *a, **k):
        return True


class _LocalClient:
    def __init__(self, binary):
        self.containers = _LocalContainers(binary)
        self.images = _LocalImages()


_orig_init = DockerTool.__init__
_orig_install = DockerTool.install
_orig_is_installed = DockerTool.is_installed
_orig_launch = DockerTool.launch


def _init(self, image, default_tag="latest"):
    self.local_bin = _local_binary(image)
    if self.local_bin:
        self.image = f"{image}:{default_tag}"
        self.client = _LocalClient(self.local_bin)
        return
    _orig_init(self, image, default_tag)


def _install(self):
    if getattr(self, "local_bin", None):
        return None
    return _orig_install(self)


def _is_installed(self):
    if getattr(self, "local_bin", None):
        return True
    return _orig_is_installed(self)


def _launch(self, command, volumes=None, timeout=30, environment=None, entrypoint=None):
    if not getattr(self, "local_bin", None):
        return _orig_launch(self, command, volumes=volumes, timeout=timeout, environment=environment, entrypoint=entrypoint)
    argv = _argv(self.local_bin, command, entrypoint)
    if _os.path.basename(self.local_bin) == "naabu" and _os.geteuid() != 0 and "-scan-type" not in argv:
        argv += ["-scan-type", "c"]  # SYN scans need root; connect scans do not
    env = dict(_os.environ)
    env["TERM"] = "dumb"
    env.update({k: str(v) for k, v in (environment or {}).items()})
    proc = _subprocess.run(argv, capture_output=True, text=True, env=env, timeout=max(int(timeout), 300))
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"{_os.path.basename(argv[0])} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return proc.stdout


DockerTool.__init__ = _init
DockerTool.install = _install
DockerTool.is_installed = _is_installed
DockerTool.launch = _launch
'''
p.write_text(s)
print("patched", p)
