"""Package the verified static workspace with its self-hosting instructions."""

from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
output = root / "web/RSAT-web-workspace.zip"
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for file in sorted((root / "web/dist").rglob("*")):
        if file.is_file():
            archive.write(file, str(file.relative_to(root / "web/dist")))
    archive.write(root / "LICENSE", "LICENSE")
    archive.write(root / "web/README.md", "README.md")
print(output)
