"""Package the verified static workspace with its self-hosting instructions."""

from pathlib import Path
import zipfile
import hashlib

root = Path(__file__).resolve().parents[1]
output = root / "web/RSAT-web-workspace.zip"
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for file in sorted((root / "web/dist").rglob("*")):
        if file.is_file():
            archive.write(file, str(file.relative_to(root / "web/dist")))
    archive.write(root / "LICENSE", "LICENSE")
    archive.write(root / "web/README.md", "README.md")
(output.parent / "RSAT-web-SHA256SUMS.txt").write_text(
    hashlib.sha256(output.read_bytes()).hexdigest() + "  " + output.name + "\n"
)
print(output)
