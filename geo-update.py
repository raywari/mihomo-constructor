import shutil
import subprocess
from pathlib import Path

REPO_URL = "https://github.com/MetaCubeX/meta-rules-dat"
REPO_BRANCH = "meta"

BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR / "meta-rules-dat"
GEO_DIR = BASE_DIR / "geo"

GEOIP_FOLDER = REPO_DIR / "geo" / "geoip"
GEOSITE_FOLDER = REPO_DIR / "geo" / "geosite"

STRIP_EXTS = {".yaml", ".mrs", ".list", ".dat", ".txt"}
DIR_EXCLUDE = {"classical"}

def run(cmd, cwd=None):
    print(f"> {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)

def remove_dir_if_exists(path: Path):
    if path.exists():
        shutil.rmtree(path)

def clone_repo(repo_url: str, target_dir: Path, branch: str = None):
    cmd = ["git", "clone"]
    if branch:
        cmd += ["--branch", branch, "--single-branch"]
    cmd += [repo_url, str(target_dir)]
    run(cmd)

def strip_known_exts(name: str, exts):
    changed = True
    while changed:
        changed = False
        for ext in exts:
            if name.endswith(ext):
                name = name[:-len(ext)]
                changed = True
    return name.rstrip(".")

def write_names_from_folder(folder: Path, out_file: Path, strip_exts=None, include_dirs=True, dir_exclude=None):
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")

    strip_exts = set(strip_exts or [])
    dir_exclude = set(dir_exclude or [])
    names = []

    for p in folder.iterdir():
        if p.is_dir():
            if include_dirs and p.name not in dir_exclude:
                names.append(p.name)
            continue
        if p.is_file():
            name = p.name
            if strip_exts:
                name = strip_known_exts(name, strip_exts)
            else:
                name = p.stem
            if name:
                names.append(name)

    names = sorted(set(names))
    out_file.write_text("\n".join(names) + "\n", encoding="utf-8")
    print(f"Wrote {len(names)} names to {out_file}")

def move_to_geo_folder(*files: Path):
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    for f in files:
        if f.exists():
            dest = GEO_DIR / f.name
            if dest.exists():
                dest.unlink()
            shutil.move(str(f), str(dest))
            print(f"Moved {f} -> {dest}")
        else:
            print(f"Skip moving, file not found: {f}")

def main():
    remove_dir_if_exists(REPO_DIR)
    clone_repo(REPO_URL, REPO_DIR, branch=REPO_BRANCH)

    geoip_txt = BASE_DIR / "geoip.txt"
    geosite_txt = BASE_DIR / "geosite.txt"

    write_names_from_folder(GEOIP_FOLDER, geoip_txt, strip_exts=STRIP_EXTS, include_dirs=True, dir_exclude=DIR_EXCLUDE)
    write_names_from_folder(GEOSITE_FOLDER, geosite_txt, strip_exts=STRIP_EXTS, include_dirs=True, dir_exclude=DIR_EXCLUDE)

    move_to_geo_folder(geoip_txt, geosite_txt)

    remove_dir_if_exists(REPO_DIR)

if __name__ == "__main__":
    main()
