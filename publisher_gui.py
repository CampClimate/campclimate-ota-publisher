#!/usr/bin/env python3

from __future__ import annotations

import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import publisher


PROJECTS_ROOT = ROOT.parent
PLATFORMIO_BIN = Path("/Users/bastian-gt/.platformio/penv/bin/pio")

TARGET_CONFIGS = {
    "basic": {
        "label": "Basic",
        "project_dir": PROJECTS_ROOT / "CampClimate Basic V2.0",
        "env": "basic-v2",
        "build_dir": Path("/tmp/campclimate_ota_publisher_basic"),
        "version_file": PROJECTS_ROOT / "CampClimate Basic V2.0" / "platformio.ini",
        "version_regex": re.compile(r'CAMPCLIMATE_BASIC_FW_VERSION=\\?"?([^"\\\s]+)\\?"?'),
    },
    "central": {
        "label": "Central",
        "project_dir": PROJECTS_ROOT / "CampClimate Central 2.0",
        "env": "central-production",
        "build_dir": Path("/tmp/campclimate_ota_publisher_central"),
        "version_file": PROJECTS_ROOT / "CampClimate Central 2.0" / "src" / "CentralApplication.cpp",
        "version_regex": re.compile(r'CENTRAL_FW_VERSION\[\]\s*=\s*"([^"]+)"'),
    },
}

RELEASE_TYPE_PRESETS = {
    "production": {"mandatory": False, "prefix": "Production release"},
    "mandatory": {"mandatory": True, "prefix": "Mandatory release"},
    "hotfix": {"mandatory": False, "prefix": "Hotfix release"},
    "test": {"mandatory": False, "prefix": "Test release"},
}


def detect_source_version(target: str) -> str:
    config = TARGET_CONFIGS[target]
    if not config["version_file"].exists():
        return ""
    text = config["version_file"].read_text(encoding="utf-8", errors="replace")
    match = config["version_regex"].search(text)
    if not match:
        return ""
    value = match.group(1).strip()
    if "_" in value:
        return value.split("_", 1)[1]
    return value


class PublisherGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("CampClimate OTA Publisher")
        self.root.geometry("1080x820")
        self.root.minsize(980, 760)

        self.worker_thread: threading.Thread | None = None
        self.event_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.current_process: subprocess.Popen[str] | None = None

        self.target_var = tk.StringVar(value="basic")
        self.mode_var = tk.StringVar(value="existing")
        self.release_type_var = tk.StringVar(value="production")
        self.version_var = tk.StringVar(value="")
        self.release_sequence_var = tk.StringVar(value="")
        self.notes_var = tk.StringVar(value="")
        self.mandatory_var = tk.BooleanVar(value=False)
        self.file_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Bereit. Release-Daten eintragen und dann veroeffentlichen.")
        self.summary_var = tk.StringVar(value="Noch kein Upload gestartet.")

        self._build_ui()
        self.refresh_defaults()
        self.root.after(100, self.process_events)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=16)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)

        ttk.Label(header, text="CampClimate OTA Publisher", font=("Helvetica", 22, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(
            header,
            text="GUI fuer OTA-Releases: vorhandenes BIN hochladen oder Produktions-Firmware frisch aus den aktuellen Quellen bauen.",
            wraplength=920,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        body = ttk.Frame(self.root, padding=(16, 0, 16, 16))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(1, weight=1)

        form = ttk.LabelFrame(body, text="Release-Daten", padding=14)
        form.grid(row=0, column=0, columnspan=2, sticky="ew")
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        ttk.Label(form, text="Target").grid(row=0, column=0, sticky="w")
        target_box = ttk.Frame(form)
        target_box.grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(target_box, text="Basic", value="basic", variable=self.target_var, command=self.refresh_defaults).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(target_box, text="Central", value="central", variable=self.target_var, command=self.refresh_defaults).grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Quelle").grid(row=0, column=2, sticky="w", padx=(18, 0))
        source_box = ttk.Frame(form)
        source_box.grid(row=0, column=3, sticky="w")
        ttk.Radiobutton(source_box, text="Vorhandenes BIN", value="existing", variable=self.mode_var, command=self.update_mode_state).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(source_box, text="Aktuelle Sources bauen", value="build", variable=self.mode_var, command=self.update_mode_state).grid(row=0, column=1, sticky="w", padx=(10, 0))

        ttk.Label(form, text="Release-Art").grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.release_type_combo = ttk.Combobox(
            form,
            textvariable=self.release_type_var,
            state="readonly",
            values=list(RELEASE_TYPE_PRESETS.keys()),
        )
        self.release_type_combo.grid(row=1, column=1, sticky="ew", pady=(12, 0))
        self.release_type_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_release_type_preset())

        ttk.Label(form, text="Version").grid(row=1, column=2, sticky="w", padx=(18, 0), pady=(12, 0))
        self.version_entry = ttk.Entry(form, textvariable=self.version_var)
        self.version_entry.grid(row=1, column=3, sticky="ew", pady=(12, 0))

        ttk.Label(form, text="Bezeichnung / Notes").grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.notes_entry = ttk.Entry(form, textvariable=self.notes_var)
        self.notes_entry.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(12, 0))

        self.mandatory_check = ttk.Checkbutton(form, text="Mandatory Update", variable=self.mandatory_var)
        self.mandatory_check.grid(row=3, column=0, sticky="w", pady=(12, 0))

        ttk.Label(form, text="Release-Sequenz").grid(
            row=3, column=2, sticky="w", padx=(18, 0), pady=(12, 0)
        )
        self.release_sequence_entry = ttk.Entry(
            form,
            textvariable=self.release_sequence_var,
        )
        self.release_sequence_entry.grid(row=3, column=3, sticky="ew", pady=(12, 0))

        ttk.Label(form, text="BIN-Datei").grid(row=4, column=0, sticky="w", pady=(12, 0))
        file_box = ttk.Frame(form)
        file_box.grid(row=4, column=1, columnspan=3, sticky="ew", pady=(12, 0))
        file_box.columnconfigure(0, weight=1)
        self.file_entry = ttk.Entry(file_box, textvariable=self.file_var)
        self.file_entry.grid(row=0, column=0, sticky="ew")
        self.file_button = ttk.Button(file_box, text="Datei waehlen", command=self.choose_file)
        self.file_button.grid(row=0, column=1, padx=(8, 0))
        ttk.Button(file_box, text="Aus drop/", command=self.choose_drop_file).grid(row=0, column=2, padx=(8, 0))

        action_row = ttk.Frame(body)
        action_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        action_row.columnconfigure(1, weight=1)
        self.publish_button = ttk.Button(action_row, text="Release veroeffentlichen", command=self.start_publish)
        self.publish_button.grid(row=0, column=0, sticky="w")
        ttk.Button(action_row, text="Felder aus Source aktualisieren", command=self.refresh_defaults).grid(
            row=0, column=1, sticky="w", padx=(12, 0)
        )

        status_frame = ttk.LabelFrame(body, text="Status", padding=12)
        status_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        status_frame.columnconfigure(0, weight=1)
        ttk.Label(status_frame, textvariable=self.status_var, wraplength=920).grid(row=0, column=0, sticky="w")
        ttk.Label(status_frame, textvariable=self.summary_var, wraplength=920, font=("Helvetica", 11, "bold")).grid(
            row=1, column=0, sticky="w", pady=(6, 0)
        )

        log_frame = ttk.LabelFrame(body, text="Build / Upload Log", padding=10)
        log_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(16, 0))
        body.rowconfigure(4, weight=1)
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(log_frame, wrap="word", font=("Menlo", 11), state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def update_mode_state(self) -> None:
        state = "normal" if self.mode_var.get() == "existing" else "disabled"
        self.file_entry.configure(state=state)
        self.file_button.state(["!disabled"] if state == "normal" else ["disabled"])
        self.refresh_defaults()

    def apply_release_type_preset(self) -> None:
        preset = RELEASE_TYPE_PRESETS[self.release_type_var.get()]
        self.mandatory_var.set(bool(preset["mandatory"]))
        current_target = TARGET_CONFIGS[self.target_var.get()]["label"]
        current_version = self.version_var.get().strip() or detect_source_version(self.target_var.get())
        self.notes_var.set(f"{current_target} {current_version} {preset['prefix']}".strip())

    def refresh_defaults(self) -> None:
        version = detect_source_version(self.target_var.get())
        if version:
            self.version_var.set(version)
        sequence = publisher.default_release_sequence(self.target_var.get())
        self.release_sequence_var.set(sequence)
        self.apply_release_type_preset()
        if self.mode_var.get() == "existing" and not self.file_var.get():
            bins = publisher.discover_bin_files()
            preferred_prefix = f"{self.target_var.get()}_"
            preferred = next((path for path in bins if path.name.lower().startswith(preferred_prefix)), None)
            if preferred:
                self.file_var.set(str(preferred))
            elif bins:
                self.file_var.set(str(bins[0]))

    def choose_file(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Firmware-BIN waehlen",
            initialdir=str(publisher.DROP_DIR),
            filetypes=[("Firmware BIN", "*.bin"), ("Alle Dateien", "*.*")],
        )
        if file_path:
            self.file_var.set(file_path)

    def choose_drop_file(self) -> None:
        bins = publisher.discover_bin_files()
        if not bins:
            messagebox.showinfo("Keine Dateien", f"Im drop-Ordner wurden keine BIN-Dateien gefunden:\n{publisher.DROP_DIR}")
            return
        file_path = filedialog.askopenfilename(
            title="BIN aus drop/ waehlen",
            initialdir=str(publisher.DROP_DIR),
            filetypes=[("Firmware BIN", "*.bin"), ("Alle Dateien", "*.*")],
        )
        if file_path:
            self.file_var.set(file_path)

    def build_firmware(self, target: str) -> Path:
        config = TARGET_CONFIGS[target]
        if not PLATFORMIO_BIN.exists():
            raise RuntimeError(f"PlatformIO wurde nicht gefunden: {PLATFORMIO_BIN}")
        if not config["project_dir"].exists():
            raise RuntimeError(f"Projektordner wurde nicht gefunden: {config['project_dir']}")

        cmd = [str(PLATFORMIO_BIN), "run", "-d", str(config["project_dir"]), "-e", str(config["env"])]
        build_env = os.environ.copy()
        build_env["PLATFORMIO_BUILD_DIR"] = str(config["build_dir"])
        self.event_queue.put(("log", f"$ {' '.join(cmd)}\n"))
        self.current_process = subprocess.Popen(
            cmd,
            cwd=str(config["project_dir"]),
            env=build_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert self.current_process.stdout is not None
        for line in self.current_process.stdout:
            self.event_queue.put(("log", line))
        return_code = self.current_process.wait()
        self.current_process = None
        if return_code != 0:
            raise RuntimeError(f"PlatformIO-Build fehlgeschlagen mit Exit-Code {return_code}.")

        firmware_path = config["build_dir"] / str(config["env"]) / "firmware.bin"
        if not firmware_path.exists():
            raise RuntimeError(f"Build erfolgreich, aber Firmware nicht gefunden: {firmware_path}")
        return firmware_path

    def validate_inputs(self) -> tuple[str, str, str, bool, int | None]:
        target = self.target_var.get().strip()
        version = self.version_var.get().strip()
        notes = self.notes_var.get().strip()
        mandatory = bool(self.mandatory_var.get())
        sequence_text = self.release_sequence_var.get().strip()
        release_sequence: int | None = None

        if target not in TARGET_CONFIGS:
            raise RuntimeError("Bitte Basic oder Central auswaehlen.")
        if not version:
            raise RuntimeError("Version darf nicht leer sein.")
        if not notes:
            raise RuntimeError("Bezeichnung / Notes darf nicht leer sein.")
        if sequence_text:
            try:
                release_sequence = int(sequence_text)
            except ValueError as exc:
                raise RuntimeError("Release-Sequenz muss eine ganze Zahl sein.") from exc
            if release_sequence < 1:
                raise RuntimeError("Release-Sequenz muss groesser oder gleich 1 sein.")
        if publisher.signing_mode() == publisher.SIGNING_MODE_REQUIRED and release_sequence is None:
            raise RuntimeError("Fuer signierte Releases ist die Release-Sequenz Pflicht.")
        if (
            publisher.signing_mode() == publisher.SIGNING_MODE_REQUIRED
            and self.mode_var.get() == "build"
        ):
            source_version = detect_source_version(target)
            if not source_version:
                raise RuntimeError(
                    "Die Firmware-Version konnte nicht sicher aus den Sources gelesen werden."
                )
            if source_version != version:
                raise RuntimeError(
                    f"Eingegebene Version {version} stimmt nicht mit der Source-Version "
                    f"{source_version} ueberein."
                )
        return target, version, notes, mandatory, release_sequence

    def start_publish(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            return
        try:
            target, version, notes, mandatory, release_sequence = self.validate_inputs()
        except RuntimeError as exc:
            messagebox.showerror("Fehlende Angaben", str(exc))
            return

        self.publish_button.state(["disabled"])
        self.status_var.set("Build/Upload gestartet.")
        self.summary_var.set("Bitte warten. Der Fortschritt erscheint unten im Log.")
        self.append_log("\n=== Neuer Publish-Lauf ===\n")

        self.worker_thread = threading.Thread(
            target=self.publish_worker,
            args=(
                target,
                version,
                notes,
                mandatory,
                release_sequence,
                self.mode_var.get(),
            ),
            daemon=True,
        )
        self.worker_thread.start()

    def publish_worker(
        self,
        target: str,
        version: str,
        notes: str,
        mandatory: bool,
        release_sequence: int | None,
        artifact_origin: str,
    ) -> None:
        try:
            if artifact_origin == "build":
                self.event_queue.put(("status", f"{TARGET_CONFIGS[target]['label']} wird aus den aktuellen Quellen gebaut..."))
                source_bin = self.build_firmware(target)
                self.event_queue.put(("log", f"Build-Artefakt: {source_bin}\n"))
            else:
                file_value = self.file_var.get().strip()
                if not file_value:
                    raise RuntimeError("Bitte eine vorhandene BIN-Datei auswaehlen.")
                source_bin = Path(file_value)
                if not source_bin.exists():
                    raise RuntimeError(f"BIN-Datei nicht gefunden: {source_bin}")

            staged_bin = publisher.stage_bin_copy(source_bin, target, version)
            self.event_queue.put(("log", f"Stage in drop/: {staged_bin}\n"))

            self.event_queue.put(("status", "Firmware-Manifest wird vorbereitet und geprueft..."))
            summary = publisher.prepare_release(
                file_path=staged_bin,
                target=target,
                version=version,
                notes=notes,
                mandatory=mandatory,
                release_sequence=release_sequence,
                artifact_origin=artifact_origin,
            )
            self.event_queue.put(("log", "Zusammenfassung:\n"))
            self.event_queue.put(("log", f"  Datei: {summary['file_name']}\n"))
            self.event_queue.put(("log", f"  Target: {summary['target']}\n"))
            self.event_queue.put(("log", f"  Version: {summary['version']}\n"))
            self.event_queue.put(("log", f"  Notes: {summary['notes']}\n"))
            self.event_queue.put(("log", f"  Mandatory: {summary['mandatory']}\n"))
            self.event_queue.put(("log", f"  SHA256: {summary['sha256']}\n"))
            self.event_queue.put(("log", f"  Public URL: {summary['public_url']}\n"))
            if summary["signed"]:
                self.event_queue.put(
                    ("log", f"  Signatur: {summary['signature_algorithm']}\n")
                )
                self.event_queue.put(("log", f"  Key-ID: {summary['signing_key_id']}\n"))
                self.event_queue.put(
                    ("log", f"  Release-Sequenz: {summary['release_sequence']}\n")
                )
                self.event_queue.put(
                    ("log", f"  Key-Fingerprint: {summary['public_key_fingerprint']}\n")
                )
            else:
                self.event_queue.put(
                    ("log", "  Signatur: DEAKTIVIERT (Legacy-/Vorbereitungsmodus)\n")
                )
            self.event_queue.put(("status", "Upload nach Supabase laeuft..."))

            result = publisher.publish_prepared_release(summary)
            release = result["release"]
            success_text = (
                f"Release erfolgreich veroeffentlicht. "
                f"ID={release.get('id', '')} | URL={result['public_url']}"
            )
            self.event_queue.put(("success", success_text))
            self.event_queue.put(("log", f"Archiviert: {result['archived_path']}\n"))
            self.event_queue.put(
                ("log", f"Release-Akte: {result['release_record_path']}\n")
            )
        except Exception as exc:
            self.event_queue.put(("error", str(exc)))
        finally:
            self.event_queue.put(("done", None))

    def process_events(self) -> None:
        while True:
            try:
                kind, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "log":
                self.append_log(str(payload))
            elif kind == "status":
                self.status_var.set(str(payload))
            elif kind == "success":
                self.status_var.set("Release erfolgreich veroeffentlicht.")
                self.summary_var.set(str(payload))
                messagebox.showinfo("Upload erfolgreich", str(payload))
            elif kind == "error":
                self.status_var.set("Fehler beim Build oder Upload.")
                self.summary_var.set(str(payload))
                messagebox.showerror("Build/Upload fehlgeschlagen", str(payload))
            elif kind == "done":
                self.publish_button.state(["!disabled"])
        self.root.after(100, self.process_events)

    def on_close(self) -> None:
        if self.current_process and self.current_process.poll() is None:
            if not messagebox.askyesno("Build laeuft", "Ein Build laeuft noch. Wirklich schliessen?"):
                return
            try:
                self.current_process.terminate()
            except Exception:
                pass
        self.root.destroy()


def main() -> int:
    root = tk.Tk()
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    PublisherGui(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
