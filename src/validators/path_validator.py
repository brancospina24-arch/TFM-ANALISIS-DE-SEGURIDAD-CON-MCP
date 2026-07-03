from pathlib import Path


BASE_DIR = Path("safe_files").resolve()


def validar_ruta_segura(ruta: str) -> Path:
    BASE_DIR.mkdir(exist_ok=True)

    ruta_final = (BASE_DIR / ruta).resolve()

    if not str(ruta_final).startswith(str(BASE_DIR)):
        raise ValueError("Path Traversal bloqueado: ruta fuera del directorio permitido.")

    return ruta_final
