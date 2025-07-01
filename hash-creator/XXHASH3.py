import os
import sys
import xxhash
import argparse
import mmap
import time
from pathlib import Path
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

# Taille max pour lecture “full load” (en octets). Les fichiers plus gros seront memory-mappés.
DEFAULT_FULL_LOAD_LIMIT = 200 * 1024 * 1024  # 200 MiB
# Nombre de threads à utiliser (par défaut nombre de cœurs CPU)
DEFAULT_NUM_THREADS = os.cpu_count() or 4


def calculate_xxhash3(file_path: Path, full_load_limit: int):
    """Compute xxHash3, en utilisant mmap pour les gros fichiers,
    et lecture directe si fichier <= full_load_limit."""
    size = file_path.stat().st_size
    h = xxhash.xxh3_64()
    with file_path.open('rb') as f:
        if size <= full_load_limit:
            data = f.read()
            h.update(data)
        else:
            with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                h.update(mm)
    return h.hexdigest(), size


def _hash_worker(args):
    f, source_dir, full_load_limit = args
    try:
        digest, size = calculate_xxhash3(f, full_load_limit)
        rel = f.relative_to(source_dir).as_posix()
        line = f"{digest} *..\\{rel}\n"
        return (line, size, 0)
    except Exception as e:
        err = f"[ERROR] {f}: {e}\n"
        return (err, 0, 1)


def human_readable(num_bytes: int) -> str:
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PiB"


def create_hashes(
    source_dir: Path,
    output_dir: Path,
    output_name: str,
    ignore_script: bool,
    full_load_limit: int,
    num_threads: int
) -> None:
    source_dir = source_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / output_name

    # Collect and filter files
    all_files = [f for f in source_dir.rglob('*') if f.is_file()]
    files = []
    script_name = Path(__file__).name
    for f in all_files:
        if f.resolve() == output_file.resolve():
            continue
        if ignore_script and f.name == script_name:
            continue
        files.append(f)

    total = len(files)
    args_iter = ((f, source_dir, full_load_limit) for f in files)

    # Stats
    total_bytes = 0
    total_errors = 0
    start_time = time.time()

    with output_file.open('w', encoding='utf-8') as out:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for line, size, err in tqdm(
                executor.map(_hash_worker, args_iter),
                total=total,
                desc=f"Hashing ({num_threads} threads)", unit="file"
            ):
                out.write(line)
                total_bytes += size
                total_errors += err

    elapsed = time.time() - start_time
    throughput = total_bytes / elapsed if elapsed > 0 else 0

    # Résumé des stats
    print(f"\nDone! Hashes saved to: {output_file}")
    print("=== Statistiques ===")
    print(f"Fichiers traités    : {total}")
    print(f"Erreurs             : {total_errors}")
    print(f"Volume total        : {human_readable(total_bytes)}")
    print(f"Temps écoulé        : {elapsed:.2f} s")
    print(f"Débit moyen         : {human_readable(int(throughput))}/s")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate xxHash3 hashes for all files in a folder, with multithreading and stats."
    )
    parser.add_argument(
        "-s", "--source", type=Path, default=Path.cwd(),
        help="Source directory (default: current dir)."
    )
    parser.add_argument(
        "-o", "--output-dir", type=Path, default=Path.cwd() / "xxHash",
        help="Output dir (default: ./xxHash)."
    )
    parser.add_argument(
        "-n", "--name", type=str, default="CRC.xxhash3",
        help="Output filename."
    )
    parser.add_argument(
        "--no-ignore-script", action="store_true",
        help="Do not ignore this script file when hashing."
    )
    parser.add_argument(
        "--full-load-limit", type=int, default=DEFAULT_FULL_LOAD_LIMIT,
        help="Max file size (bytes) to load fully in RAM (default: 200 MiB)."
    )
    parser.add_argument(
        "--threads", type=int, default=DEFAULT_NUM_THREADS,
        help="Number of threads to use (default: CPU cores)."
    )

    args = parser.parse_args()

    create_hashes(
        source_dir=args.source,
        output_dir=args.output_dir,
        output_name=args.name,
        ignore_script=not args.no_ignore_script,
        full_load_limit=args.full_load_limit,
        num_threads=args.threads
    )

    input("\nPress Enter to exit...")
