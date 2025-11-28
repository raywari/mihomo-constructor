import shutil
import subprocess
from pathlib import Path

GEOIP_REPO = "https://github.com/v2fly/geoip/"
GEOSITE_REPO = "https://github.com/v2fly/domain-list-community"

BASE_DIR = Path(__file__).resolve().parent
GEOIP_DIR = BASE_DIR / "geoip"
GEOSITE_DIR = BASE_DIR / "domain-list-community"
GEO_DIR = BASE_DIR / "geo"

def run(cmd, cwd=None):
    print(f"> {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)

def remove_dir_if_exists(path: Path):
    if path.exists():
        print(f"Removing folder: {path}")
        shutil.rmtree(path)

def clone_repo(repo_url: str, target_dir: Path, branch: str = None):
    cmd = ["git", "clone"]
    if branch:
        cmd += ["--branch", branch, "--single-branch"]
    cmd += [repo_url, str(target_dir)]
    run(cmd)

def write_names_from_folder(folder: Path, out_file: Path, strip_ext: str = None):
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")

    names = []
    for p in folder.iterdir():
        if p.is_file():
            if strip_ext and p.name.endswith(strip_ext):
                names.append(p.name[:-len(strip_ext)])
            else:
                names.append(p.stem)

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
    remove_dir_if_exists(GEOIP_DIR)
    remove_dir_if_exists(GEOSITE_DIR)

    clone_repo(GEOIP_REPO, GEOIP_DIR, branch="release")
    clone_repo(GEOSITE_REPO, GEOSITE_DIR)

    geoip_text_folder = GEOIP_DIR / "text"
    geoip_txt = BASE_DIR / "geoip.txt"
    write_names_from_folder(geoip_text_folder, geoip_txt, strip_ext=".txt")

    geosite_data_folder = GEOSITE_DIR / "data"
    geosite_txt = BASE_DIR / "geosite.txt"
    write_names_from_folder(geosite_data_folder, geosite_txt)

    move_to_geo_folder(geoip_txt, geosite_txt)

if __name__ == "__main__":
    main()
