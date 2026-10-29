"""Derive the scanner input SBOMs from the raw Syft output (documented, deterministic modifications only):
drop `file` components and the project's own self-component (they are not third-party dependencies), keep every library untouched, and set
metadata.component to an `application` subject carrying the SHA-256 of a reproducible tarball of the project directory (used by the evidence tool's
artifact binding). Raw Syft files stay in sbom_raw/ unmodified."""
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def tar_sha256(directory: Path) -> str:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in sorted(p for p in directory.rglob("*") if p.is_file()):
            info = tar.gettarinfo(str(path), arcname=str(path.relative_to(directory)))
            info.mtime = 0; info.uid = info.gid = 0; info.uname = info.gname = ""
            with path.open("rb") as handle:
                tar.addfile(info, handle)
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def main() -> None:
    out_dir = HERE / "sbom_clean"
    out_dir.mkdir(exist_ok=True)
    for raw_path in sorted((HERE / "sbom_raw").glob("sbom_raw_*.json")):
        project = raw_path.stem.removeprefix("sbom_raw_")
        doc = json.loads(raw_path.read_text())
        keep = [c for c in doc["components"] if c["type"] == "library" and not re.search(rf"[/:@]{re.escape(project)}@1\.0\.0|^{re.escape(project)}$", c.get("purl", "") or c["name"]) and c.get("purl")]
        dropped = [c.get("purl") or c["name"] for c in doc["components"] if c not in keep]
        digest = tar_sha256(HERE / "projects" / project)
        doc["components"] = keep
        doc["metadata"]["component"] = {"bom-ref": f"product:{project}", "type": "application", "name": project, "version": "1.0.0",
                                        "hashes": [{"alg": "SHA-256", "content": digest}]}
        doc["dependencies"] = [{"ref": c["bom-ref"]} for c in keep]
        (out_dir / f"{project}.json").write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        print(f"{project}: {len(keep)} libraries kept; dropped {dropped}; subject sha256 {digest[:12]}…")


if __name__ == "__main__":
    main()
