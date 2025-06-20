# PyIdle - Quellcode
# Entwickler: Tobias Schug


# Module Importieren
import datetime, logging, psutil, time, win32api, yaml
from logging.handlers import RotatingFileHandler
from schedule import Scheduler
from typing import Dict, Set


# Globale Variablen
PYIDLE_VERSION = "v1.0.1"
PYIDLE_BUILD = "20250620"
MAX_LOG_SIZE = 1 * 1024 * 1024


# Klasse: SafeScheduler
class SafeScheduler(Scheduler):
    def __init__(self, reschedule_on_failure=True):
        # Legt fest, ob Jobs bei einem Fehler automatisch neu geplant werden sollen
        self.reschedule_on_failure = reschedule_on_failure
        super().__init__()
    def _run_job(self, job):
        # Führt einen Job aus und fängt dabei Ausnahmen ab
        try:
            super()._run_job(job)
        except Exception as err:
            logging.exception(f"Unerwarteter Fehler {err=}, {type(err)=}")
            if self.reschedule_on_failure:
                job.last_run = datetime.datetime.now()
                job._schedule_next_run()


# Funktion: Prozesse prüfen und beenden
def check_and_terminate_processes(config: Dict, logger: logging.Logger) -> None:
    debug = config.get('runtime_debug', False)
    # Leerlauf-Schwellenwert in Sekunden
    threshold = config.get('threshold', 1800)
    # Liste der zu überwachenden Prozessnamen
    processes_to_check = config.get('processes', [])
    if not processes_to_check:
        if debug:
            logger.debug("Keine Prozesse zum Überprüfen konfiguriert.")
        return
    # Set der Prozessnamen in Kleinbuchstaben für effizienten Vergleich
    check_names_lower: Set[str] = {name.lower() for name in processes_to_check}
    # Set der Prozessnamen mit .exe Endung in Kleinbuchstaben
    check_names_exe_lower: Set[str] = {f"{name.lower()}.exe" for name in processes_to_check}
    found_processes = []
    # Durchsuche alle laufenden Prozesse, um die zu überwachenden Prozesse zu finden
    try:
        # Iteriere durch alle laufenden Prozesse
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_info = proc.info
                proc_name_lower = proc_info['name'].lower()
                # Prüfe, ob der aktuelle Prozessname in der Liste der zu überwachenden Prozesse ist
                if proc_name_lower in check_names_lower or proc_name_lower in check_names_exe_lower:
                    found_processes.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                if debug:
                    pid = getattr(proc, 'pid', 'N/A')
                    logger.debug(f"Überspringe Prozess PID {pid} aufgrund eines Fehlers beim Zugriff: {e}")
            except Exception as e:
                pid = getattr(proc, 'pid', 'N/A')
                logger.error(f"Fehler beim Zugriff auf Informationen für Prozess PID {pid}: {e}")
    except Exception as e:
        logger.exception(f"Unerwarteter Fehler beim Iterieren durch Prozesse: {e}")
        return
    # Wenn keine der Zielprozesse laufen, beende die Funktion
    if not found_processes:
        if debug:
            logger.debug("Keine der konfigurierten Prozesse laufen aktuell.")
        return
    # Ermittle die aktuelle System-Leerlaufzeit
    idle_time = get_idle_time()
    if debug:
        process_names = [p.info.get('name', 'unknown') for p in found_processes]
        logger.debug(f"Leerlaufzeit: {idle_time:.2f}s - Gefundene Prozesse: {process_names}")
    # Wenn die Leerlaufzeit den Schwellenwert überschreitet
    if idle_time > threshold:
        terminated_count = 0
        errors = []
        successfully_terminated_names = []
        # Versuche, jeden gefundenen Zielprozess ordnungsgemäß zu beenden
        for proc in found_processes:
            proc_name = proc.info.get('name', f"PID {proc.pid}") if proc.info else f"PID {proc.pid}"
            proc_pid = proc.pid
            try:
                if debug:
                    logger.debug(f"Versuche Prozess {proc_name} (PID: {proc_pid}) ordnungsgemäß zu beenden (terminate)")
                proc.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                errors.append(f"Konnte {proc_name} (PID: {proc_pid}) nicht beenden: {e}")
            except Exception as e:
                logger.exception(f"Unerwarteter Fehler beim Beenden von {proc_name} (PID: {proc_pid}): {e}")
                errors.append(f"Unerwarteter Fehler beim Beenden von {proc_name} (PID: {proc_pid}): {e}")
        # Warte kurz, um den Prozessen Zeit zum Beenden zu geben
        try:
            gone, alive = psutil.wait_procs(found_processes, timeout=1)
            terminated_count += len(gone)
            for p in gone:
                p_name = p.info.get('name', f"PID {p.pid}") if p.info else f"PID {p.pid}"
                successfully_terminated_names.append(p_name)
            # Erzwinge das Beenden von Prozessen, die nicht ordnungsgemäß beendet wurden
            for p in alive:
                proc_name = p.info.get('name', f"PID {p.pid}") if p.info else f"PID {p.pid}"
                proc_pid = p.pid
                logger.warning(f"Prozess {proc_name} (PID: {proc_pid}) wurde nicht ordnungsgemäß beendet, erzwinge Beendigung (kill).")
                try:
                    p.kill()
                    terminated_count += 1
                    successfully_terminated_names.append(f"{proc_name} (beendet/killed)")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    errors.append(f"Konnte Beendigung (Kill) von {proc_name} (PID: {proc_pid}) nicht erzwingen: {e}")
                except Exception as e:
                    logger.exception(f"Unerwarteter Fehler beim Beenden (Kill) von {proc_name} (PID: {proc_pid}): {e}")
        except Exception as e:
            logger.exception(f"Fehler während der Prozess Warte-/Kill-Phase: {e}")
        # Logge die Ergebnisse des Beendigungsvorgangs
        if terminated_count > 0:
            logger.info(f"System im Leerlauf für > {threshold}s. {terminated_count} Prozess(e) beendet: {', '.join(successfully_terminated_names)}.")
        if errors:
            for error_msg in errors:
                logger.error(error_msg)
        # Wenn Prozesse gefunden wurden, aber keiner beendet werden konnte
        elif terminated_count == 0 and found_processes:
            process_names = [p.info.get('name', 'unknown') for p in found_processes]
            logger.warning(f"System im Leerlauf, aber es konnten keine Zielprozesse beendet werden: {process_names}")


# Funktion: Leerlaufzeit ermitteln
def get_idle_time() -> float:
    # Systemzeit seit dem Start in Millisekunden
    tick_count = win32api.GetTickCount() & 0xFFFFFFFF
    # Zeitpunkt der letzten Benutzereingabe in Millisekunden
    last_input = win32api.GetLastInputInfo() & 0xFFFFFFFF
    # Differenz in Sekunden
    return (tick_count - last_input) / 1000.0


# Funktion: Logger Initialisierung
def init_logger(name: str, log_file: str, current_config: Dict) -> logging.Logger:
    logger = logging.getLogger(name)
    # Setze Log-Level basierend auf Konfiguration
    level=logging.DEBUG if current_config.get('runtime_debug') else logging.INFO
    # Konfiguriere den Logger nur, wenn er noch keine Handler hat
    if not logger.handlers:
        logger.setLevel(level)
        # Rotiere Log-Datei bei 1MB, behalte 2 Backups
        handler = RotatingFileHandler(filename=log_file, mode='a', maxBytes=MAX_LOG_SIZE, backupCount=2)
        # Definiere das Format für Log-Nachrichten
        handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt="%d.%m.%Y - %H:%M:%S"))
        logger.addHandler(handler)
    # Deaktiviere andere Logger, um nur Nachrichten von diesem Skript zu loggen
    for log_name, log_obj in logging.Logger.manager.loggerDict.items():
        # Stelle sicher, dass nur Logger-Instanzen dieses Skripts aktiv bleiben
        if log_name != name:
            # Sicherstellen, dass es ein Logger-Objekt ist
            if isinstance(log_obj, logging.Logger):
                log_obj.disabled = True
    return logger


# Funktion: Konfigurationsdatei laden
def load_config(file_path: str) -> Dict:
    try:
        # Öffne und parse die YAML-Konfigurationsdatei
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except (FileNotFoundError, yaml.YAMLError) as e:
        logging.error(f"Fehler beim Laden der Konfigurationsdatei {file_path}: {e}")
        raise


# Python Skript ausführen
if __name__ == '__main__':
    # Lädt die Konfiguration aus der YAML-Datei
    config = load_config('PyIdle.yaml')
    # Initialisiert den Logger
    logger = init_logger(__name__, 'PyIdle.log', config)
    logger.info(f"Starte PyIdle {PYIDLE_VERSION} (Build: {PYIDLE_BUILD}) - - Leerlauf-Schwellenwert in Sekunden: {config.get('threshold', 1800)}{' - Debug-Modus: aktiv' if config.get('runtime_debug') else ''}")
    # Initialisiere den Scheduler
    scheduler = SafeScheduler(reschedule_on_failure=True)
    # Plane die periodische Ausführung der Prozessüberprüfung
    scheduler.every(config.get('interval', 60)).seconds.do(check_and_terminate_processes, config=config, logger=logger)
    # Hauptschleife des Programms
    while True:
        try:
            # Führe anstehende Jobs aus
            scheduler.run_pending()
            # Zeit bis zum nächsten geplanten Job
            time.sleep(1)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt empfangen. Wird heruntergefahren...")
            # Beende die Schleife bei Strg+C
            break
        except Exception as e:
            logger.exception(f"Fehler in der Hauptschleife: {e}")
            # Warte kurz bei einem unerwarteten Fehler, bevor die Schleife fortgesetzt wird
            time.sleep(5)
    logger.info("PyIdle gestoppt.")