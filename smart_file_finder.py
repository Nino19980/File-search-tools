import os
import sys
import hashlib
import zipfile
import time
import threading
import queue
import re
import logging
import json
import shutil
import tempfile
import datetime
from enum import Enum
import traceback
from typing import List, Dict, Any, Tuple, Set, Optional, Union, Callable

# Importazione condizionale delle librerie di GUI e AI
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from tkinter.font import Font
    HAS_TK = True
except ImportError:
    HAS_TK = False
    
try:
    import PyQt5.QtWidgets as QtWidgets
    import PyQt5.QtCore as QtCore
    import PyQt5.QtGui as QtGui
    HAS_QT = True
except ImportError:
    HAS_QT = False

# Tentiamo di importare le librerie di AI
try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    HAS_AI_LIBS = True
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt', quiet=True)
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('stopwords', quiet=True)
except ImportError:
    HAS_AI_LIBS = False

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("smart_file_finder.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SmartFileFinder")

# Costanti
DEFAULT_EXTENSIONS = [".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
MAX_PREVIEW_SIZE = 100 * 1024  # 10KB
DEFAULT_AI_THRESHOLD = 0.3
CHUNK_SIZE = 8192  # Per la lettura dei file
MAX_THREADS = 8

class FileCategory(Enum):
    """Enumerazione delle categorie di file."""
    DOCUMENT = "Documenti"
    SPREADSHEET = "Fogli di calcolo"
    PRESENTATION = "Presentazioni"
    IMAGE = "Immagini"
    VIDEO = "Video"
    AUDIO = "Audio"
    CODE = "Codice"
    ARCHIVE = "Archivi"
    DATABASE = "Database"
    EXECUTABLE = "Eseguibili"
    UNKNOWN = "Sconosciuto"

class ForensicAlgorithm(Enum):
    """Enumerazione degli algoritmi forensi disponibili."""
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"
    ALL = "Tutti"

class PermissionLevel(Enum):
    """Livelli di permesso necessari."""
    NORMAL = "Normale"
    ADMIN = "Amministratore"

class FileInfo:
    """Classe per memorizzare informazioni sui file trovati."""
    
    def __init__(self, path: str, name: str, size: int, category: FileCategory = FileCategory.UNKNOWN):
        self.path = path
        self.name = name
        self.size = size
        self.category = category
        self.hashes = {}
        self.preview = None
        self.last_modified = os.path.getmtime(os.path.join(path, name))
        self.last_accessed = os.path.getatime(os.path.join(path, name))
        self.creation_time = os.path.getctime(os.path.join(path, name))
        self.extension = os.path.splitext(name)[1].lower()
        self.mime_type = self._get_mime_type()
        self.ai_score = 0.0  # Punteggio di rilevanza AI
        
    def full_path(self) -> str:
        """Restituisce il percorso completo del file."""
        return os.path.join(self.path, self.name)
    
    def _get_mime_type(self) -> str:
        """Determina il tipo MIME del file."""
        import mimetypes
        mime_type, _ = mimetypes.guess_type(self.name)
        return mime_type if mime_type else "application/octet-stream"
    
    def get_formatted_size(self) -> str:
        """Restituisce la dimensione del file formattata."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.size < 1024.0:
                return f"{self.size:.2f} {unit}"
            self.size /= 1024.0
        return f"{self.size:.2f} TB"
    
    def get_formatted_date(self, timestamp: float) -> str:
        """Converte un timestamp in una data formattata."""
        return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    
    def calculate_hash(self, algorithm: ForensicAlgorithm) -> str:
        """Calcola l'hash del file con l'algoritmo specificato."""
        if algorithm in self.hashes:
            return self.hashes[algorithm]
        
        hasher = None
        if algorithm == ForensicAlgorithm.MD5:
            hasher = hashlib.md5()
        elif algorithm == ForensicAlgorithm.SHA1:
            hasher = hashlib.sha1()
        elif algorithm == ForensicAlgorithm.SHA256:
            hasher = hashlib.sha256()
        elif algorithm == ForensicAlgorithm.SHA512:
            hasher = hashlib.sha512()
        
        if hasher:
            try:
                with open(self.full_path(), 'rb') as f:
                    for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                        hasher.update(chunk)
                hash_value = hasher.hexdigest()
                self.hashes[algorithm] = hash_value
                return hash_value
            except (IOError, PermissionError) as e:
                logger.error(f"Errore nel calcolo dell'hash per {self.full_path()}: {e}")
                return "Errore"
        return "Algoritmo non supportato"
    
    def generate_preview(self) -> str:
        """Genera un'anteprima del contenuto del file."""
        if self.preview:
            return self.preview
        
        try:
            if self.extension in ['.txt', '.py', '.c', '.cpp', '.h', '.java', '.js', '.html', '.css', '.xml', '.json']:
                with open(self.full_path(), 'r', errors='ignore') as f:
                    self.preview = f.read(MAX_PREVIEW_SIZE)
                    if len(self.preview) == MAX_PREVIEW_SIZE:
                        self.preview += "...[contenuto troncato]"
            else:
                self.preview = "[Anteprima non disponibile per questo tipo di file]"
        except Exception as e:
            self.preview = f"[Errore nella generazione dell'anteprima: {str(e)}]"
        
        return self.preview
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in un dizionario per la serializzazione."""
        return {
            'path': self.path,
            'name': self.name,
            'size': self.size,
            'category': self.category.value,
            'hashes': self.hashes,
            'last_modified': self.last_modified,
            'last_accessed': self.last_accessed,
            'creation_time': self.creation_time,
            'extension': self.extension,
            'mime_type': self.mime_type,
            'ai_score': self.ai_score
        }

class AIEngine:
    """Motore di intelligenza artificiale per la ricerca e categorizzazione di file."""
    
    def __init__(self, threshold: float = DEFAULT_AI_THRESHOLD):
        self.threshold = threshold
        self.vectorizer = None
        self.init_ai()
    
    def init_ai(self) -> None:
        """Inizializza il motore AI."""
        if not HAS_AI_LIBS:
            logger.warning("Librerie AI non disponibili. Funzionalità AI limitate.")
            return
        
        self.vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words=stopwords.words('italian') + stopwords.words('english'),
            ngram_range=(1, 2)
        )
    
    def categorize_file(self, file_info: FileInfo) -> FileCategory:
        """Categorizza un file in base all'estensione e al contenuto."""
        ext = file_info.extension.lower()
        
        # Categorizzazione basata su estensione
        if ext in ['.txt', '.doc', '.docx', '.pdf', '.rtf', '.odt']:
            return FileCategory.DOCUMENT
        elif ext in ['.xls', '.xlsx', '.csv', '.ods']:
            return FileCategory.SPREADSHEET
        elif ext in ['.ppt', '.pptx', '.odp']:
            return FileCategory.PRESENTATION
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp']:
            return FileCategory.IMAGE
        elif ext in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm']:
            return FileCategory.VIDEO
        elif ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma']:
            return FileCategory.AUDIO
        elif ext in ['.py', '.java', '.c', '.cpp', '.h', '.js', '.html', '.css', '.php', '.rb', '.go', '.rust', '.ts']:
            return FileCategory.CODE
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return FileCategory.ARCHIVE
        elif ext in ['.db', '.sqlite', '.sql', '.mdb', '.accdb']:
            return FileCategory.DATABASE
        elif ext in ['.exe', '.dll', '.so', '.dylib', '.bin', '.app']:
            return FileCategory.EXECUTABLE
        
        # Se l'AI è disponibile, proviamo un'analisi più approfondita per file non riconosciuti
        if HAS_AI_LIBS and ext in ['.txt']:
            preview = file_info.generate_preview()
            # L'analisi del contenuto potrebbe essere usata per categorizzare meglio
            # Qui potremmo utilizzare un classificatore addestrato o euristica
        
        return FileCategory.UNKNOWN
    
    def score_file_relevance(self, file_info: FileInfo, search_text: str) -> float:
        """Calcola un punteggio di rilevanza del file rispetto alla query di ricerca."""
        if not search_text:
            return 1.0  # Se non c'è un testo di ricerca, tutti i file sono rilevanti
            
        # Verifica prima se la query è presente nel nome del file (peso maggiore)
        filename = file_info.name.lower()
        search_lower = search_text.lower()
        name_match = search_lower in filename
        
        # Punteggio base se c'è una corrispondenza nel nome
        if name_match:
            return 1.0 - (len(filename) - len(search_lower)) / (len(filename) * 2)
        
        if not HAS_AI_LIBS or not self.vectorizer:
            # Fallback a ricerca semplice quando l'AI non è disponibile
            # Qui controlliamo anche se la stringa è nel contenuto del file
            if not file_info.preview:
                file_info.generate_preview()
                
            if file_info.preview and search_lower in file_info.preview.lower():
                # Match nel contenuto ma non nel nome (peso minore)
                return 0.6
            return 0.0
        
        try:
            # Generiamo anteprima se non già disponibile
            if not file_info.preview:
                file_info.generate_preview()
            
            # Se non abbiamo contenuto testuale, usiamo solo il nome
            if not file_info.preview or file_info.preview.startswith('['):
                content = file_info.name
            else:
                content = file_info.preview
            
            # Vectorizziamo il contenuto e la query
            documents = [content, search_text]
            tfidf_matrix = self.vectorizer.fit_transform(documents)
            
            # Calcoliamo la similarità del coseno
            cosine_sim = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            return float(cosine_sim)
        except Exception as e:
            logger.error(f"Errore nel calcolo della rilevanza AI: {e}")
            return 0.0
    
    def filter_by_relevance(self, files: List[FileInfo], search_text: str) -> List[FileInfo]:
        """Filtra i file in base alla rilevanza rispetto alla query di ricerca."""
        for file in files:
            file.ai_score = self.score_file_relevance(file, search_text)
        
        return [f for f in files if f.ai_score >= self.threshold]

class FileSearcher:
    """Gestore della ricerca dei file."""
    
    def __init__(self, ai_engine: AIEngine):
        self.ai_engine = ai_engine
        self.stop_event = threading.Event()
        self.files_queue = queue.Queue()
        self.progress_callback = None
        self.search_threads = []
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]) -> None:
        """Imposta il callback per il progresso della ricerca."""
        self.progress_callback = callback
    
    def search_files(self, 
                    start_paths: List[str], 
                    search_text: str, 
                    extensions: List[str] = None, 
                    max_depth: int = -1,
                    recursive: bool = True) -> List[FileInfo]:
        """
        Cerca file che corrispondono ai criteri specificati.
        
        Args:
            start_paths: Elenco di percorsi in cui iniziare la ricerca
            search_text: Testo da cercare nei nomi dei file
            extensions: Estensioni dei file da cercare (None = tutte)
            max_depth: Profondità massima di ricerca nelle sottodirectory (-1 = illimitata)
            recursive: Se True, cerca anche nelle sottodirectory
            
        Returns:
            Lista di oggetti FileInfo che rappresentano i file trovati
        """
        # Reset dello stato precedente
        self.stop_event.clear()
        self.files_queue = queue.Queue()
        self.search_threads = []
        
        # Normalizza le estensioni
        if extensions:
            extensions = [e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions]
        
        # Crea thread di ricerca per ogni percorso iniziale
        thread_count = min(MAX_THREADS, len(start_paths))
        paths_per_thread = [[] for _ in range(thread_count)]
        
        # Distribuisci i percorsi tra i thread
        for i, path in enumerate(start_paths):
            paths_per_thread[i % thread_count].append(path)
        
        # Avvia i thread di ricerca
        for i, paths in enumerate(paths_per_thread):
            if not paths:
                continue
            thread = threading.Thread(
                target=self._search_thread,
                args=(paths, search_text, extensions, max_depth, recursive),
                name=f"SearchThread-{i}"
            )
            thread.daemon = True
            thread.start()
            self.search_threads.append(thread)
        
        # Raccogli i risultati
        all_files = []
        files_checked = 0
        dirs_checked = 0
        
        last_update = time.time()
        while any(t.is_alive() for t in self.search_threads) or not self.files_queue.empty():
            try:
                item = self.files_queue.get(timeout=0.1)
                if isinstance(item, FileInfo):
                    all_files.append(item)
                elif isinstance(item, tuple) and len(item) == 2:
                    files_checked, dirs_checked = item
                
                self.files_queue.task_done()
                
                # Aggiorna il progresso ogni 250ms
                current_time = time.time()
                if self.progress_callback and current_time - last_update > 0.25:
                    last_update = current_time
                    self.progress_callback(files_checked, dirs_checked, 
                                          f"Trovati {len(all_files)} file...")
                
            except queue.Empty:
                continue
            
            if self.stop_event.is_set():
                break
        
        # Filtro per rilevanza AI
        if search_text:
            all_files = self.ai_engine.filter_by_relevance(all_files, search_text)
        
        # Ordina per punteggio di rilevanza
        all_files.sort(key=lambda x: x.ai_score, reverse=True)
        
        if self.progress_callback:
            self.progress_callback(files_checked, dirs_checked, 
                                 f"Ricerca completata. Trovati {len(all_files)} file rilevanti.")
        
        return all_files
    
    def _search_thread(self, 
                      start_paths: List[str], 
                      search_text: str, 
                      extensions: List[str], 
                      max_depth: int,
                      recursive: bool) -> None:
        """Thread di ricerca che esplora directory e sottodirectory."""
        files_checked = 0
        dirs_checked = 0
        
        for start_path in start_paths:
            if not os.path.exists(start_path):
                logger.warning(f"Il percorso {start_path} non esiste")
                continue
            
            for root, dirs, files in os.walk(start_path):
                if self.stop_event.is_set():
                    return
                
                # Controlla la profondità
                if max_depth >= 0:
                    relative_path = os.path.relpath(root, start_path)
                    depth = len(relative_path.split(os.sep)) if relative_path != '.' else 0
                    if depth > max_depth:
                        dirs.clear()  # Impedisce di andare più in profondità
                        continue
                
                # Incrementa il conteggio delle directory
                dirs_checked += 1
                
                # Se non ricorsivo, svuota la lista delle directory
                if not recursive:
                    dirs.clear()
                
                # Controlla i file
                for name in files:
                    if self.stop_event.is_set():
                        return
                    
                    files_checked += 1
                    
                    # Applica filtro per estensione
                    _, ext = os.path.splitext(name)
                    if extensions and ext.lower() not in extensions:
                        continue
                    
                    try:
                        file_path = os.path.join(root, name)
                        if os.path.isfile(file_path):
                            size = os.path.getsize(file_path)
                            file_info = FileInfo(root, name, size)
                            file_info.category = self.ai_engine.categorize_file(file_info)
                            self.files_queue.put(file_info)
                    except (PermissionError, OSError) as e:
                        logger.error(f"Errore nell'accesso al file {os.path.join(root, name)}: {e}")
                
                # Aggiorna il conteggio
                self.files_queue.put((files_checked, dirs_checked))
    
    def stop_search(self) -> None:
        """Ferma tutte le ricerche in corso."""
        self.stop_event.set()
        for thread in self.search_threads:
            if thread.is_alive():
                thread.join(1.0)  # Attendi massimo 1 secondo

class CompressionEngine:
    """Motore di compressione dei file."""
    
    def __init__(self):
        self.progress_callback = None
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]) -> None:
        """Imposta il callback per il progresso della compressione."""
        self.progress_callback = callback
    
    def compress_files(self, files: List[FileInfo], output_path: str, 
                      compression_level: int = 6) -> Optional[str]:
        """
        Comprime una lista di file in un archivio ZIP.
        
        Args:
            files: Lista di FileInfo da comprimere
            output_path: Percorso in cui salvare l'archivio compresso
            compression_level: Livello di compressione (0-9, 9 = massima)
            
        Returns:
            Percorso dell'archivio compresso o None in caso di errore
        """
        if not files:
            return None
        
        # Assicurati che output_path abbia l'estensione .zip
        if not output_path.lower().endswith('.zip'):
            output_path += '.zip'
        
        try:
            total_files = len(files)
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, 
                                 compresslevel=compression_level) as zipf:
                
                # Aggiungi un file di metadati con informazioni sui file
                metadata = {
                    'creation_date': datetime.datetime.now().isoformat(),
                    'file_count': total_files,
                    'files': [f.to_dict() for f in files]
                }
                zipf.writestr('metadata.json', json.dumps(metadata, indent=2))
                
                # Comprimi tutti i file
                for i, file_info in enumerate(files):
                    if self.progress_callback:
                        self.progress_callback(i, total_files, 
                                              f"Compressione del file {i+1}/{total_files}: {file_info.name}")
                    
                    try:
                        # Usa un nome file che include il percorso relativo originale
                        arcname = os.path.join(os.path.basename(file_info.path), file_info.name)
                        zipf.write(file_info.full_path(), arcname=arcname)
                    except (PermissionError, OSError) as e:
                        logger.error(f"Errore nella compressione di {file_info.full_path()}: {e}")
            
            if self.progress_callback:
                self.progress_callback(total_files, total_files, 
                                     f"Compressione completata: {output_path}")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Errore nella creazione dell'archivio: {e}")
            return None

class ForensicEngine:
    """Motore per l'analisi forense dei file."""
    
    def __init__(self):
        self.progress_callback = None
    
    def set_progress_callback(self, callback: Callable[[int, int, str], None]) -> None:
        """Imposta il callback per il progresso dell'analisi forense."""
        self.progress_callback = callback
    
    def analyze_files(self, files: List[FileInfo], 
                     algorithms: List[ForensicAlgorithm] = None) -> Dict[str, Dict[str, str]]:
        """
        Analizza una lista di file calcolando gli hash forensi.
        
        Args:
            files: Lista di FileInfo da analizzare
            algorithms: Algoritmi di hash da utilizzare
            
        Returns:
            Dizionario con i risultati dell'analisi
        """
        if not files:
            return {}
        
        if not algorithms:
            algorithms = [ForensicAlgorithm.MD5, ForensicAlgorithm.SHA256]
        elif ForensicAlgorithm.ALL in algorithms:
            algorithms = [algo for algo in ForensicAlgorithm if algo != ForensicAlgorithm.ALL]
        
        results = {}
        total_files = len(files)
        
        for i, file_info in enumerate(files):
            file_path = file_info.full_path()
            if self.progress_callback:
                self.progress_callback(i, total_files, 
                                      f"Analisi del file {i+1}/{total_files}: {file_info.name}")
            
            file_results = {}
            for algorithm in algorithms:
                hash_value = file_info.calculate_hash(algorithm)
                file_results[algorithm.value] = hash_value
            
            results[file_path] = file_results
        
        if self.progress_callback:
            self.progress_callback(total_files, total_files, 
                                 f"Analisi forense completata per {total_files} file")
        
        return results
    
    def export_report(self, files: List[FileInfo], 
                     algorithms: List[ForensicAlgorithm], 
                     output_path: str) -> Optional[str]:
        """
        Esporta un report forense completo.
        
        Args:
            files: Lista di FileInfo da includere nel report
            algorithms: Algoritmi di hash utilizzati
            output_path: Percorso in cui salvare il report
            
        Returns:
            Percorso del report o None in caso di errore
        """
        if not files:
            return None
        
        try:
            # Crea il report in formato JSON
            report = {
                'creation_date': datetime.datetime.now().isoformat(),
                'file_count': len(files),
                'algorithms_used': [algo.value for algo in algorithms],
                'files': []
            }
            
            for file_info in files:
                file_data = file_info.to_dict()
                hashes = {}
                for algorithm in algorithms:
                    hashes[algorithm.value] = file_info.calculate_hash(algorithm)
                file_data['hashes'] = hashes
                report['files'].append(file_data)
            
            # Assicurati che output_path abbia l'estensione .json
            if not output_path.lower().endswith('.json'):
                output_path += '.json'
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            
            return output_path
            
        except Exception as e:
            logger.error(f"Errore nella creazione del report: {e}")
            return None

class PermissionHandler:
    """Gestore dei permessi di sistema per operazioni che richiedono privilegi elevati."""
    
    @staticmethod
    def is_admin() -> bool:
        """Verifica se l'applicazione è in esecuzione con privilegi amministrativi."""
        try:
            if sys.platform == 'win32':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Su Unix, controlla se l'utente è root (UID 0)
                return os.geteuid() == 0
        except:
            return False
    
    @staticmethod
    def elevate_privileges() -> bool:
        """Tenta di elevare i privilegi dell'applicazione."""
        try:
            if sys.platform == 'win32':
                # Su Windows, riavvia il processo con flag "runas"
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, f'"{sys.argv[0]}"', None, 1
                    )
                    sys.exit(0)
                return True
            else:
                # Su Unix, si potrebbe usare sudo, ma non è consigliabile
                # per applicazioni grafiche. Meglio richiedere all'utente
                # di rilanciare l'applicazione con sudo.
                return False
        except Exception as e:
            logger.error(f"Errore nell'elevazione dei privilegi: {e}")
            return False
    
    @staticmethod
    def has_permission(path: str) -> bool:
        """Verifica se l'utente ha permessi di accesso a un percorso."""
        try:
            # Verifica accesso in lettura
            readable = os.access(path, os.R_OK)
            # Verifica se è una directory
            if os.path.isdir(path):
                # Verifica se è possibile elencare i contenuti
                try:
                    os.listdir(path)
                    return True
                except:
                    return False
            return readable
        except:
            return False

# Implementazione GUI con Tkinter
class TkinterGUI:
    """Implementazione dell'interfaccia grafica con Tkinter."""
    
    def __init__(self, app):
        self.app = app
        self.root = tk.Tk()
        self.root.title("Smart File Finder")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Configura stili
        self.configure_styles()
        
        # Crea l'interfaccia
        self.create_menu()
        self.create_ui()
        
        # Configura gestione eventi
        self.setup_event_handlers()
        
        # Configura thread separato per operazioni lunghe
        self.worker_queue = queue.Queue()
        self.stop_worker = threading.Event()
        self.worker_thread = None
        
        # Avvia il timer per controllare la coda di lavoro
        self.root.after(100, self.check_worker_queue)
    
    def configure_styles(self):
        """Configura stili e temi dell'applicazione."""
        style = ttk.Style()
        if sys.platform == 'win32':
            style.theme_use('vista')
        elif sys.platform == 'darwin':
            style.theme_use('aqua')
        else:
            style.theme_use('clam')
        
        # Configura font
        default_font = ('Segoe UI' if sys.platform == 'win32' else 'Helvetica', 10)
        title_font = ('Segoe UI' if sys.platform == 'win32' else 'Helvetica', 12, 'bold')
        
        style.configure('TButton', font=default_font, padding=5)
        style.configure('TLabel', font=default_font)
        style.configure('Header.TLabel', font=title_font)
        style.configure('TEntry', font=default_font)
        style.configure('TCheckbutton', font=default_font)
        style.configure('Treeview', font=default_font, rowheight=25)
        style.configure('Treeview.Heading', font=default_font, padding=5)
        
        self.default_font = default_font
        self.title_font = title_font
    
    def create_menu(self):
        """Crea il menu dell'applicazione."""
        menubar = tk.Menu(self.root)
        
        # Menu File
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Nuova ricerca", command=self.reset_search)
        file_menu.add_separator()
        file_menu.add_command(label="Esporta risultati...", command=self.export_results)
        file_menu.add_command(label="Comprimi file selezionati...", command=self.compress_selected)
        file_menu.add_separator()
        file_menu.add_command(label="Esci", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Menu Strumenti
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Analisi forense...", command=self.forensic_analysis)
        tools_menu.add_command(label="Impostazioni IA...", command=self.show_ai_settings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Esegui come amministratore", 
                              command=self.app.permission_handler.elevate_privileges)
        menubar.add_cascade(label="Strumenti", menu=tools_menu)
        
        # Menu Aiuto
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Guida", command=self.show_help)
        help_menu.add_command(label="Informazioni", command=self.show_about)
        menubar.add_cascade(label="Aiuto", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_ui(self):
        """Crea l'interfaccia utente principale."""
        # Frame principale
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Area superiore: controlli di ricerca
        search_frame = ttk.LabelFrame(main_frame, text="Parametri di ricerca", padding=10)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Percorso di ricerca
        path_frame = ttk.Frame(search_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Percorso:").pack(side=tk.LEFT, padx=(0, 5))
        self.path_var = tk.StringVar(value="")
        self.path_entry = ttk.Entry(path_frame, textvariable=self.path_var)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(path_frame, text="Sfoglia...", command=self.browse_path).pack(side=tk.LEFT)
        
        # Testo di ricerca
        text_frame = ttk.Frame(search_frame)
        text_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(text_frame, text="Testo da cercare:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_text_var = tk.StringVar()
        ttk.Entry(text_frame, textvariable=self.search_text_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Opzioni di ricerca
        options_frame = ttk.Frame(search_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        # Estensioni dei file (modifica)
        ext_frame = ttk.Frame(options_frame)
        ext_frame.grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=(0, 5))

        ttk.Label(ext_frame, text="Estensioni:").pack(side=tk.LEFT, padx=(0, 5))
        self.extensions_var = tk.StringVar(value=".txt, .pdf, .doc, .docx")
        ttk.Entry(ext_frame, textvariable=self.extensions_var, width=30).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(ext_frame, text="Scegli estensioni...", 
                command=self.create_extension_selector_dialog).pack(side=tk.LEFT)

        # Ricerca ricorsiva
        self.recursive_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Ricerca ricorsiva", variable=self.recursive_var).grid(row=0, column=2, padx=5)
        
        # Profondità massima
        ttk.Label(options_frame, text="Profondità max:").grid(row=0, column=3, sticky=tk.W, padx=5)
        self.max_depth_var = tk.StringVar(value="-1")
        depth_entry = ttk.Entry(options_frame, textvariable=self.max_depth_var, width=5)
        depth_entry.grid(row=0, column=4, sticky=tk.W, padx=5)
        
        # Pulsante di ricerca
        ttk.Button(options_frame, text="Avvia ricerca", command=self.start_search).grid(row=0, column=5, padx=5)
        ttk.Button(options_frame, text="Ferma", command=self.stop_search).grid(row=0, column=6, padx=5)
        
        options_frame.columnconfigure(1, weight=1)
        
        # Area centrale: risultati
        results_frame = ttk.LabelFrame(main_frame, text="Risultati della ricerca", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Creazione della tabella dei risultati
        columns = ('name', 'path', 'size', 'category', 'modified', 'score')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings')
        
        # Definizione delle intestazioni
        self.results_tree.heading('name', text='Nome')
        self.results_tree.heading('path', text='Percorso')
        self.results_tree.heading('size', text='Dimensione')
        self.results_tree.heading('category', text='Categoria')
        self.results_tree.heading('modified', text='Ultima modifica')
        self.results_tree.heading('score', text='Punteggio IA')
        
        # Definizione delle larghezze delle colonne
        self.results_tree.column('name', width=200)
        self.results_tree.column('path', width=250)
        self.results_tree.column('size', width=100)
        self.results_tree.column('category', width=120)
        self.results_tree.column('modified', width=150)
        self.results_tree.column('score', width=100)
        
        # Aggiunta delle scrollbar
        tree_scrollbar_y = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scrollbar_y.set)
        
        tree_scrollbar_x = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(xscrollcommand=tree_scrollbar_x.set)
        
        # Posizionamento degli elementi
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Area inferiore: anteprima e dettagli
        details_frame = ttk.LabelFrame(main_frame, text="Dettagli file", padding=10)
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Creazione dell'area di anteprima
        self.preview_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10, 
                                                     font=('Courier New', 10))
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        
        # Area di stato: barra di stato e progresso
        status_frame = ttk.Frame(main_frame, padding=(0, 5, 0, 0))
        status_frame.pack(fill=tk.X, padx=5)
        
        # Barra di progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(side=tk.TOP, fill=tk.X)
        
        # Barra di stato
        self.status_var = tk.StringVar(value="Pronto")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=(5, 0))
        
        # Etichetta admin
        admin_text = "Admin" if self.app.permission_handler.is_admin() else "Utente standard"
        admin_label = ttk.Label(status_frame, text=admin_text, anchor=tk.E)
        admin_label.pack(side=tk.RIGHT, pady=(5, 0))
    
    def create_extension_selector_dialog(self):
        """Crea una finestra di dialogo per selezionare le estensioni dei file."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Seleziona Estensioni")
        dialog.geometry("650x500")  # Finestra più larga per supportare il layout orizzontale
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Frame principale
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Intestazione
        ttk.Label(main_frame, text="Seleziona le estensioni di file da includere nella ricerca:", 
                font=self.title_font).pack(anchor=tk.W, pady=(0, 10))
        
        # Frame per le categorie
        categories_frame = ttk.Frame(main_frame)
        categories_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Crea un notebook con schede per le diverse categorie
        notebook = ttk.Notebook(categories_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Definiamo le categorie di estensioni
        categories = {
            "Documenti": [".txt", ".pdf", ".doc", ".docx", ".rtf", ".odt", ".md", ".tex"],
            "Fogli di calcolo": [".xls", ".xlsx", ".csv", ".ods", ".numbers"],
            "Presentazioni": [".ppt", ".pptx", ".odp", ".key"],
            "Immagini": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp"],
            "Video": [".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm"],
            "Audio": [".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma"],
            "Codice": [".py", ".java", ".c", ".cpp", ".h", ".js", ".html", ".css", ".php", ".rb", ".go", ".rs", ".ts"],
            "Database": [".db", ".sqlite", ".sql", ".mdb", ".accdb", ".dbf", ".mdf", ".ndf", ".bak", ".frm", ".ibd", ".myi", ".myd"],
            "Archivi": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
            "Altri": [".exe", ".dll", ".so", ".app", ".json", ".xml", ".log", ".ini", ".conf", ".yaml", ".yml"]
        }
        
        # Dizionario per tenere traccia delle variabili delle checkbox
        self.extension_vars = {}
        
        # Crea una scheda per ogni categoria
        for category, extensions in categories.items():
            # Crea un frame per la categoria
            category_frame = ttk.Frame(notebook, padding=10)
            notebook.add(category_frame, text=category)
            
            # Pulsanti Seleziona tutti / Deseleziona tutti
            buttons_frame = ttk.Frame(category_frame)
            buttons_frame.pack(fill=tk.X, pady=(0, 10))
            
            def select_all(category=category):
                for ext in categories[category]:
                    if ext in self.extension_vars:
                        self.extension_vars[ext].set(True)
            
            def deselect_all(category=category):
                for ext in categories[category]:
                    if ext in self.extension_vars:
                        self.extension_vars[ext].set(False)
            
            ttk.Button(buttons_frame, text="Seleziona tutti", 
                    command=lambda cat=category: select_all(cat)).pack(side=tk.LEFT, padx=5)
            ttk.Button(buttons_frame, text="Deseleziona tutti", 
                    command=lambda cat=category: deselect_all(cat)).pack(side=tk.LEFT, padx=5)
            
            # Crea un frame con scrollbar per le checkbox
            scroll_frame = ttk.Frame(category_frame)
            scroll_frame.pack(fill=tk.BOTH, expand=True)
            
            canvas = tk.Canvas(scroll_frame)
            scrollbar = ttk.Scrollbar(scroll_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e, canvas=canvas: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Layout orizzontale per le checkbox (3 colonne)
            checkbox_frames = [ttk.Frame(scrollable_frame) for _ in range(3)]
            for frame in checkbox_frames:
                frame.pack(side=tk.LEFT, fill=tk.Y, expand=True, padx=5)
            
            # Ottieni le estensioni correnti
            current_exts = self.get_extensions_list()
            
            # Distribuisci le checkbox nelle colonne
            for i, ext in enumerate(extensions):
                column = i % 3  # Determina in quale colonna va questa checkbox
                
                var = tk.BooleanVar(value=False)
                self.extension_vars[ext] = var
                
                # Se l'estensione è già nel campo, selezionala
                if current_exts and ext in current_exts:
                    var.set(True)
                
                ttk.Checkbutton(checkbox_frames[column], text=ext, variable=var).pack(anchor=tk.W, pady=2)
        
        # Frame per estensioni personalizzate
        custom_frame = ttk.LabelFrame(main_frame, text="Estensioni personalizzate", padding=10)
        custom_frame.pack(fill=tk.X, pady=10)
        
        # Campo di testo per estensioni personalizzate
        ttk.Label(custom_frame, text="Inserisci estensioni personalizzate separate da virgole:").pack(anchor=tk.W, pady=(0, 5))
        
        # Prendiamo le estensioni attuali che non sono nel nostro elenco predefinito
        all_predefined_exts = [ext for exts in categories.values() for ext in exts]
        custom_exts = []
        current_exts = self.get_extensions_list()
        if current_exts:
            custom_exts = [ext for ext in current_exts if ext not in all_predefined_exts]
        
        self.custom_exts_var = tk.StringVar(value=", ".join(custom_exts))
        ttk.Entry(custom_frame, textvariable=self.custom_exts_var).pack(fill=tk.X, pady=5)
        
        # Frame per i pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Pulsante per selezionare tutte le estensioni
        def select_all_extensions():
            for var in self.extension_vars.values():
                var.set(True)
        
        def deselect_all_extensions():
            for var in self.extension_vars.values():
                var.set(False)
        
        ttk.Button(button_frame, text="Seleziona tutte", 
                command=select_all_extensions).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Deseleziona tutte", 
                command=deselect_all_extensions).pack(side=tk.LEFT, padx=5)
        
        # Aggiunta: Data e utente
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user_info = f"Utente: {os.getlogin()}"
        
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(5, 0))
        ttk.Label(info_frame, text=f"{user_info} | {current_time}", 
                font=('Segoe UI', 8)).pack(side=tk.LEFT)
        
        # Pulsanti di azione
        ttk.Button(button_frame, text="Annulla", 
                command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Applica", 
                command=lambda: self._apply_extension_selection(dialog)).pack(side=tk.RIGHT, padx=5)

    def _apply_extension_selection(self, dialog):
        """Applica la selezione delle estensioni."""
        # Raccogli le estensioni selezionate
        selected_exts = []
        for ext, var in self.extension_vars.items():
            if var.get():
                selected_exts.append(ext)
        
        # Aggiungi le estensioni personalizzate
        custom_exts_text = self.custom_exts_var.get()
        if custom_exts_text:
            custom_exts = [ext.strip() for ext in custom_exts_text.split(',')]
            for ext in custom_exts:
                if not ext:
                    continue
                ext = ext if ext.startswith('.') else f'.{ext}'
                if ext not in selected_exts:
                    selected_exts.append(ext)
        
        # Imposta il valore nel campo delle estensioni
        self.extensions_var.set(", ".join(selected_exts))
        
        # Chiudi la finestra
        dialog.destroy()

    def setup_event_handlers(self):
        """Configura i gestori degli eventi."""
        # Doppio click su un file per visualizzare l'anteprima
        self.results_tree.bind('<Double-1>', self.show_file_details)
        
        # Click destro per menu contestuale
        self.results_tree.bind('<Button-3>', self.show_context_menu)
        
        # Gestione chiusura finestra
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def browse_path(self):
        """Apre un dialogo per selezionare il percorso di ricerca."""
        directory = filedialog.askdirectory(initialdir=self.path_var.get())
        if directory:
            self.path_var.set(directory)
    
    def get_extensions_list(self) -> List[str]:
        """Converte la stringa delle estensioni in una lista."""
        extensions_text = self.extensions_var.get().strip()
        if not extensions_text:
            return None  # Tutte le estensioni
        
        # Dividi la stringa per virgole e pulisci ogni elemento
        extensions = [ext.strip() for ext in extensions_text.split(',')]
        # Assicurati che ogni estensione inizi con un punto
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        return extensions
    
    def update_progress(self, current, total, message=None):
        """Aggiorna la barra di progresso e il messaggio di stato."""
        if total > 0:
            progress = (current / total) * 100
            self.progress_var.set(progress)
        else:
            self.progress_var.set(0)
        
        if message:
            self.status_var.set(message)
        
        # Forza l'aggiornamento dell'interfaccia
        self.root.update_idletasks()
    
    def start_search(self):
        """Avvia la ricerca dei file."""
        # Verifica che il percorso esista
        search_path = self.path_var.get()
        if not os.path.exists(search_path):
            messagebox.showerror("Errore", f"Il percorso '{search_path}' non esiste")
            return
        
        # Verifica i permessi
        if not self.app.permission_handler.has_permission(search_path):
            result = messagebox.askyesno("Permessi insufficienti", 
                                       "Non hai permessi sufficienti per accedere a questa cartella. "
                                       "Vuoi eseguire l'applicazione come amministratore?")
            if result:
                self.app.permission_handler.elevate_privileges()
                return
        
        # Ottieni gli altri parametri
        search_text = self.search_text_var.get()
        extensions = self.get_extensions_list()
        recursive = self.recursive_var.get()
        
        try:
            max_depth = int(self.max_depth_var.get())
        except ValueError:
            max_depth = -1  # Valore predefinito
        
        # Cancella i risultati precedenti
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Reimposta la barra di progresso
        self.progress_var.set(0)
        self.status_var.set("Avvio della ricerca...")
        
        # Avvia la ricerca in un thread separato
        self.search_params = {
            'start_paths': [search_path],
            'search_text': search_text,
            'extensions': extensions,
            'max_depth': max_depth,
            'recursive': recursive
        }
        
        self.launch_worker(self._search_worker)
    
    def _search_worker(self):
        """Thread worker per la ricerca dei file."""
        try:
            # Imposta il callback di progresso
            self.app.file_searcher.set_progress_callback(
                lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
            )
            
            # Avvia la ricerca
            results = self.app.file_searcher.search_files(**self.search_params)
            
            # Invia i risultati alla coda
            self.worker_queue.put(('results', results))
            
        except Exception as e:
            self.worker_queue.put(('error', str(e)))
    
    def update_results(self, files: List[FileInfo]):
        """Aggiorna la tabella dei risultati con i file trovati."""
        # Cancella i risultati precedenti
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Aggiungi i nuovi risultati
        for file_info in files:
            values = (
                file_info.name,
                file_info.path,
                file_info.get_formatted_size(),
                file_info.category.value,
                file_info.get_formatted_date(file_info.last_modified),
                f"{file_info.ai_score:.2f}" if file_info.ai_score > 0 else "-"
            )
            self.results_tree.insert('', tk.END, values=values, tags=(file_info.full_path(),))
    
    def stop_search(self):
        """Ferma la ricerca in corso."""
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_worker.set()
            self.app.file_searcher.stop_search()
            self.status_var.set("Interruzione della ricerca...")
    
    def show_file_details(self, event):
        """Mostra i dettagli di un file selezionato."""
        item_id = self.results_tree.focus()
        if not item_id:
            return
        
        # Ottieni il percorso del file dalle tag dell'elemento
        tags = self.results_tree.item(item_id, 'tags')
        if not tags:
            return
        
        file_path = tags[0]
        if not os.path.exists(file_path):
            messagebox.showerror("Errore", f"Il file '{file_path}' non esiste più")
            return
        
        # Crea un oggetto FileInfo per il file
        path, name = os.path.split(file_path)
        size = os.path.getsize(file_path)
        file_info = FileInfo(path, name, size)
        
        # Genera l'anteprima
        preview = file_info.generate_preview()
        
        # Aggiorna l'area di anteprima
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.insert(tk.END, preview)
    
    def show_context_menu(self, event):
        """Mostra il menu contestuale per un elemento selezionato."""
        item_id = self.results_tree.identify_row(event.y)
        if not item_id:
            return
        
        # Seleziona l'elemento
        self.results_tree.selection_set(item_id)
        
        # Crea il menu contestuale
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="Apri", command=self.open_selected_file)
        context_menu.add_command(label="Apri cartella", command=self.open_selected_folder)
        context_menu.add_separator()
        context_menu.add_command(label="Analisi forense", command=lambda: self.forensic_analysis([item_id]))
        context_menu.add_separator()
        context_menu.add_command(label="Copia percorso", command=self.copy_path_to_clipboard)
        
        # Mostra il menu
        context_menu.tk_popup(event.x_root, event.y_root)
    
    def open_selected_file(self):
        """Apre il file selezionato con l'applicazione predefinita."""
        item_id = self.results_tree.focus()
        if not item_id:
            return
        
        tags = self.results_tree.item(item_id, 'tags')
        if not tags:
            return
        
        file_path = tags[0]
        if not os.path.exists(file_path):
            messagebox.showerror("Errore", f"Il file '{file_path}' non esiste più")
            return
        
        # Apri il file con l'applicazione predefinita
        try:
            if sys.platform == 'win32':
                os.startfile(file_path)
            elif sys.platform == 'darwin':
                os.system(f'open "{file_path}"')
            else:
                os.system(f'xdg-open "{file_path}"')
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile aprire il file: {str(e)}")
    
    def open_selected_folder(self):
        """Apre la cartella contenente il file selezionato."""
        item_id = self.results_tree.focus()
        if not item_id:
            return
        
        tags = self.results_tree.item(item_id, 'tags')
        if not tags:
            return
        
        file_path = tags[0]
        folder_path = os.path.dirname(file_path)
        
        if not os.path.exists(folder_path):
            messagebox.showerror("Errore", f"La cartella '{folder_path}' non esiste più")
            return
        
        # Apri la cartella con l'applicazione predefinita
        try:
            if sys.platform == 'win32':
                os.startfile(folder_path)
            elif sys.platform == 'darwin':
                os.system(f'open "{folder_path}"')
            else:
                os.system(f'xdg-open "{folder_path}"')
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile aprire la cartella: {str(e)}")
    
    def copy_path_to_clipboard(self):
        """Copia il percorso del file selezionato negli appunti."""
        item_id = self.results_tree.focus()
        if not item_id:
            return
        
        tags = self.results_tree.item(item_id, 'tags')
        if not tags:
            return
        
        file_path = tags[0]
        
        # Copia negli appunti
        self.root.clipboard_clear()
        self.root.clipboard_append(file_path)
        self.status_var.set(f"Percorso copiato: {file_path}")
    
    def reset_search(self):
        """Reimposta i parametri di ricerca."""
        self.search_text_var.set("")
        self.extensions_var.set(".txt, .pdf, .doc, .docx")
        self.recursive_var.set(True)
        self.max_depth_var.set("-1")
        
        # Cancella i risultati
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Reimposta la barra di progresso
        self.progress_var.set(0)
        self.status_var.set("Pronto")
    
    def export_results(self):
        """Esporta i risultati della ricerca in un file JSON."""
        # Verifica se ci sono risultati
        if not self.results_tree.get_children():
            messagebox.showinfo("Informazione", "Non ci sono risultati da esportare")
            return
        
        # Chiedi il nome del file
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("File JSON", "*.json"), ("Tutti i file", "*.*")],
            title="Esporta risultati"
        )
        
        if not file_path:
            return
        
        # Raccolta i dati
        results = []
        for item_id in self.results_tree.get_children():
            values = self.results_tree.item(item_id, 'values')
            tags = self.results_tree.item(item_id, 'tags')
            if not tags:
                continue
            
            file_path = tags[0]
            path, name = os.path.split(file_path)
            
            try:
                size = os.path.getsize(file_path)
                file_info = FileInfo(path, name, size)
                results.append(file_info.to_dict())
            except (FileNotFoundError, PermissionError):
                # Ignora i file che non esistono più o non sono accessibili
                pass
        
        # Esporta i dati
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'export_date': datetime.datetime.now().isoformat(),
                    'file_count': len(results),
                    'files': results
                }, f, indent=2)
            
            self.status_var.set(f"Risultati esportati in {file_path}")
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile esportare i risultati: {str(e)}")
    
    def compress_selected(self):
        """Comprime i file selezionati."""
        # Ottieni i file selezionati
        selected_ids = self.results_tree.selection()
        if not selected_ids:
            messagebox.showinfo("Informazione", "Nessun file selezionato")
            return
        
        # Chiedi il nome del file di output
        output_path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("File ZIP", "*.zip"), ("Tutti i file", "*.*")],
            title="Comprimi file"
        )
        
        if not output_path:
            return
        
        # Raccogli i dati dei file
        files_to_compress = []
        for item_id in selected_ids:
            tags = self.results_tree.item(item_id, 'tags')
            if not tags:
                continue
            
            file_path = tags[0]
            if not os.path.exists(file_path):
                continue
            
            path, name = os.path.split(file_path)
            size = os.path.getsize(file_path)
            file_info = FileInfo(path, name, size)
            files_to_compress.append(file_info)
        
        if not files_to_compress:
            messagebox.showinfo("Informazione", "Nessun file valido selezionato")
            return
        
        # Imposta il callback di progresso
        self.app.compression_engine.set_progress_callback(
            lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
        )
        
        # Avvia la compressione in un thread separato
        self.launch_worker(lambda: self._compress_worker(files_to_compress, output_path))
    
    def _compress_worker(self, files, output_path):
        """Thread worker per la compressione dei file."""
        try:
            result = self.app.compression_engine.compress_files(files, output_path)
            if result:
                self.worker_queue.put(('success', f"File compressi in {result}"))
            else:
                self.worker_queue.put(('error', "Errore nella compressione dei file"))
        except Exception as e:
            self.worker_queue.put(('error', str(e)))
    
    def forensic_analysis(self, selected_ids=None):
        """Esegue l'analisi forense dei file selezionati."""
        # Se non sono stati specificati ID, usa la selezione corrente
        if not selected_ids:
            selected_ids = self.results_tree.selection()
        
        if not selected_ids:
            messagebox.showinfo("Informazione", "Nessun file selezionato")
            return
        
        # Crea una finestra di dialogo per le opzioni forensi
        dialog = tk.Toplevel(self.root)
        dialog.title("Analisi forense")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Frame principale
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Algoritmi
        algo_frame = ttk.LabelFrame(main_frame, text="Algoritmi di hash", padding=10)
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Variabili per gli algoritmi
        self.md5_var = tk.BooleanVar(value=True)
        self.sha1_var = tk.BooleanVar(value=False)
        self.sha256_var = tk.BooleanVar(value=True)
        self.sha512_var = tk.BooleanVar(value=False)
        
        # Checkbutton per gli algoritmi
        ttk.Checkbutton(algo_frame, text="MD5", variable=self.md5_var).pack(anchor=tk.W)
        ttk.Checkbutton(algo_frame, text="SHA-1", variable=self.sha1_var).pack(anchor=tk.W)
        ttk.Checkbutton(algo_frame, text="SHA-256", variable=self.sha256_var).pack(anchor=tk.W)
        ttk.Checkbutton(algo_frame, text="SHA-512", variable=self.sha512_var).pack(anchor=tk.W)
        
        # Opzioni report
        report_frame = ttk.LabelFrame(main_frame, text="Opzioni report", padding=10)
        report_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Variabile per il report
        self.create_report_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(report_frame, text="Crea report", variable=self.create_report_var).pack(anchor=tk.W)
        
        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Annulla", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Analizza", 
                  command=lambda: self._start_forensic_analysis(selected_ids, dialog)).pack(side=tk.RIGHT, padx=5)
    
    def _start_forensic_analysis(self, selected_ids, dialog):
        """Avvia l'analisi forense con le opzioni selezionate."""
        # Raccogli gli algoritmi selezionati
        algorithms = []
        if self.md5_var.get():
            algorithms.append(ForensicAlgorithm.MD5)
        if self.sha1_var.get():
            algorithms.append(ForensicAlgorithm.SHA1)
        if self.sha256_var.get():
            algorithms.append(ForensicAlgorithm.SHA256)
        if self.sha512_var.get():
            algorithms.append(ForensicAlgorithm.SHA512)
        
        if not algorithms:
            messagebox.showwarning("Attenzione", "Seleziona almeno un algoritmo")
            return
        
        # Raccogli i dati dei file
        files_to_analyze = []
        for item_id in selected_ids:
            tags = self.results_tree.item(item_id, 'tags')
            if not tags:
                continue
            
            file_path = tags[0]
            if not os.path.exists(file_path):
                continue
            
            path, name = os.path.split(file_path)
            size = os.path.getsize(file_path)
            file_info = FileInfo(path, name, size)
            files_to_analyze.append(file_info)
        
        if not files_to_analyze:
            messagebox.showinfo("Informazione", "Nessun file valido selezionato")
            return
        
        # Chiudi la finestra di dialogo
        dialog.destroy()
        
        # Se l'utente vuole creare un report, chiedi il percorso
        report_path = None
        if self.create_report_var.get():
            report_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("File JSON", "*.json"), ("Tutti i file", "*.*")],
                title="Salva report forense"
            )
            
            if not report_path:
                messagebox.showinfo("Informazione", "Analisi forense annullata")
                return
        
        # Imposta il callback di progresso
        self.app.forensic_engine.set_progress_callback(
            lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
        )
        
        # Avvia l'analisi in un thread separato
        self.launch_worker(lambda: self._forensic_worker(files_to_analyze, algorithms, report_path))

    def _forensic_worker(self, files, algorithms, report_path=None):
        """Thread worker per l'analisi forense."""
        try:
            # Esegui l'analisi
            results = self.app.forensic_engine.analyze_files(files, algorithms)
            
            # Crea il report se richiesto
            if report_path:
                self.app.forensic_engine.export_report(files, algorithms, report_path)
                self.worker_queue.put(('success', f"Report forense salvato in {report_path}"))
            
            # Prepara il messaggio con i risultati
            file_count = len(files)
            algo_count = len(algorithms)
            self.worker_queue.put(('success', f"Analisi forense completata per {file_count} file con {algo_count} algoritmi"))
            
            # Mostra i risultati in una nuova finestra
            self.worker_queue.put(('show_forensic_results', results, files, algorithms))
            
        except Exception as e:
            self.worker_queue.put(('error', str(e)))

    def show_forensic_results(self, results, files, algorithms):
        """Mostra i risultati dell'analisi forense in una finestra separata."""
        # Crea una nuova finestra
        result_window = tk.Toplevel(self.root)
        result_window.title("Risultati Analisi Forense")
        result_window.geometry("800x600")
        result_window.minsize(600, 400)
        
        # Frame principale
        main_frame = ttk.Frame(result_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Crea una tabella per i risultati
        columns = ['file', 'path']
        for algo in algorithms:
            columns.append(algo.value)
        
        result_tree = ttk.Treeview(main_frame, columns=columns, show='headings')
        
        # Definizione delle intestazioni
        result_tree.heading('file', text='Nome file')
        result_tree.heading('path', text='Percorso')
        for algo in algorithms:
            result_tree.heading(algo.value, text=algo.value)
        
        # Definizione delle larghezze delle colonne
        result_tree.column('file', width=150)
        result_tree.column('path', width=250)
        for algo in algorithms:
            result_tree.column(algo.value, width=150)
        
        # Aggiunta delle scrollbar
        tree_scrollbar_y = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=result_tree.yview)
        result_tree.configure(yscrollcommand=tree_scrollbar_y.set)
        
        tree_scrollbar_x = ttk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=result_tree.xview)
        result_tree.configure(xscrollcommand=tree_scrollbar_x.set)
        
        # Posizionamento degli elementi
        result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Aggiungi i risultati alla tabella
        for file_info in files:
            file_path = file_info.full_path()
            if file_path in results:
                values = [file_info.name, file_info.path]
                for algo in algorithms:
                    if algo.value in results[file_path]:
                        values.append(results[file_path][algo.value])
                    else:
                        values.append("-")
                result_tree.insert('', tk.END, values=values)
        
        # Pulsanti di azione
        button_frame = ttk.Frame(result_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(button_frame, text="Chiudi", command=result_window.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Esporta CSV...", 
                command=lambda: self._export_forensic_csv(results, files, algorithms)).pack(side=tk.RIGHT, padx=5)

    def _export_forensic_csv(self, results, files, algorithms):
        """Esporta i risultati dell'analisi forense in un file CSV."""
        # Chiedi il percorso del file
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("File CSV", "*.csv"), ("Tutti i file", "*.*")],
            title="Esporta risultati"
        )
        
        if not file_path:
            return
        
        try:
            import csv
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Crea l'intestazione
                fieldnames = ['Nome file', 'Percorso']
                for algo in algorithms:
                    fieldnames.append(algo.value)
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Scrivi i dati
                for file_info in files:
                    file_path = file_info.full_path()
                    if file_path in results:
                        row = {
                            'Nome file': file_info.name,
                            'Percorso': file_info.path
                        }
                        for algo in algorithms:
                            if algo.value in results[file_path]:
                                row[algo.value] = results[file_path][algo.value]
                            else:
                                row[algo.value] = ""
                        writer.writerow(row)
            
            self.status_var.set(f"Risultati forensi esportati in CSV")
            
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile esportare i risultati: {str(e)}")

    def show_ai_settings(self):
        """Mostra le impostazioni dell'IA."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Impostazioni IA")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Frame principale
        main_frame = ttk.Frame(dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Informazioni sulle librerie
        info_frame = ttk.LabelFrame(main_frame, text="Stato librerie IA", padding=10)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Verifica lo stato delle librerie
        ai_status = "Installate e operative" if HAS_AI_LIBS else "Non disponibili"
        ttk.Label(info_frame, text=f"Librerie IA: {ai_status}").pack(anchor=tk.W, pady=2)
        
        # Elenca le librerie
        libraries = [
            ("NumPy", "numpy"),
            ("Scikit-learn", "sklearn"),
            ("NLTK", "nltk")
        ]
        
        for name, module in libraries:
            try:
                __import__(module)
                status = "✓ Installata"
            except ImportError:
                status = "✗ Non installata"
            ttk.Label(info_frame, text=f"{name}: {status}").pack(anchor=tk.W, pady=2)
        
        # Impostazioni di soglia
        settings_frame = ttk.LabelFrame(main_frame, text="Impostazioni di soglia", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Soglia di rilevanza (0.0-1.0):").pack(anchor=tk.W, pady=2)
        
        # Imposta il valore attuale
        threshold_var = tk.DoubleVar(value=self.app.ai_engine.threshold)
        threshold_scale = ttk.Scale(settings_frame, from_=0.0, to=1.0, 
                                variable=threshold_var, orient=tk.HORIZONTAL)
        threshold_scale.pack(fill=tk.X, pady=5)
        
        # Etichetta del valore attuale
        threshold_label = ttk.Label(settings_frame, text=f"{threshold_var.get():.2f}")
        threshold_label.pack(anchor=tk.E, pady=2)
        
        # Aggiorna l'etichetta quando il valore cambia
        def update_threshold_label(*args):
            threshold_label.config(text=f"{threshold_var.get():.2f}")
        
        threshold_var.trace_add("write", update_threshold_label)
        
        # Pulsanti
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Annulla", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Applica", 
                command=lambda: self._apply_ai_settings(threshold_var.get(), dialog)).pack(side=tk.RIGHT, padx=5)

    def _apply_ai_settings(self, threshold, dialog):
        """Applica le nuove impostazioni dell'IA."""
        # Aggiorna la soglia
        self.app.ai_engine.threshold = threshold
        
        # Chiudi la finestra
        dialog.destroy()
        
        # Aggiorna lo stato
        self.status_var.set(f"Impostazioni IA aggiornate: soglia di rilevanza = {threshold:.2f}")

    def show_help(self):
        """Mostra la guida dell'applicazione."""
        help_window = tk.Toplevel(self.root)
        help_window.title("Guida - Smart File Finder")
        help_window.geometry("700x500")
        help_window.minsize(600, 400)
        
        # Frame principale
        main_frame = ttk.Frame(help_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Area di testo per la guida
        help_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=('Segoe UI', 10))
        help_text.pack(fill=tk.BOTH, expand=True)
        
        # Disabilita la modifica
        help_text.config(state=tk.NORMAL)
        
        # Contenuto della guida
        guide = """# Guida a Smart File Finder

    ## Introduzione
    Smart File Finder è un'applicazione avanzata per la ricerca di file che utilizza l'intelligenza artificiale per trovare, categorizzare e analizzare i file sul tuo sistema.

    ## Funzionalità principali

    ### Ricerca di file
    1. Inserisci il percorso in cui cercare o usa "Sfoglia..." per selezionarlo.
    2. Inserisci il testo da cercare nei nomi dei file.
    3. Specifica le estensioni di file da includere (separate da virgole).
    4. Scegli se la ricerca deve essere ricorsiva e la profondità massima.
    5. Clicca su "Avvia ricerca" per iniziare.

    ### Risultati della ricerca
    - I risultati vengono visualizzati nella tabella centrale.
    - Fai doppio clic su un file per visualizzarne l'anteprima.
    - Usa il menu contestuale (clic destro) per ulteriori opzioni.

    ### Compressione
    - Seleziona uno o più file nei risultati.
    - Scegli "Comprimi file selezionati..." dal menu File.
    - Seleziona il percorso di output per l'archivio ZIP.

    ### Analisi forense
    - Seleziona uno o più file nei risultati.
    - Scegli "Analisi forense..." dal menu Strumenti.
    - Seleziona gli algoritmi di hash da utilizzare.
    - Visualizza o esporta i risultati.

    ## Suggerimenti
    - Per una ricerca più precisa, utilizza parole chiave specifiche.
    - L'IA migliorerà la rilevanza dei risultati in base al contenuto dei file.
    - Per accedere a cartelle protette, esegui l'applicazione come amministratore.

    ## Requisiti
    - Python 3.6 o superiore
    - Librerie: numpy, scikit-learn, nltk (opzionali per funzionalità IA avanzate)

    ## Supporto
    Per problemi o suggerimenti, contatta il supporto tecnico.
    """
        
        # Inserisci il testo della guida
        help_text.insert(tk.END, guide)
        
        # Blocca la modifica
        help_text.config(state=tk.DISABLED)
        
        # Pulsante di chiusura
        ttk.Button(help_window, text="Chiudi", command=help_window.destroy).pack(pady=10)

    def show_about(self):
        """Mostra informazioni sull'applicazione."""
        messagebox.showinfo(
            "Informazioni su Smart File Finder",
            "Smart File Finder v1.0\n\n"
            "Un'applicazione avanzata per la ricerca di file con IA.\n\n"
            "Caratteristiche:\n"
            "- Ricerca intelligente di file\n"
            "- Categorizzazione automatica\n"
            "- Compressione integrata\n"
            "- Analisi forense\n\n"
            "Sviluppato per Nino19980\n"
            f"Data: {datetime.datetime.now().strftime('%Y-%m-%d')}"
        )

    def launch_worker(self, worker_func):
        """Avvia un thread worker per operazioni lunghe."""
        # Ferma il thread precedente se è in esecuzione
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_worker.set()
            self.worker_thread.join(1.0)
        
        # Reimposta il flag di stop
        self.stop_worker.clear()
        
        # Avvia il nuovo thread
        self.worker_thread = threading.Thread(target=worker_func)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def check_worker_queue(self):
        """Controlla la coda di lavoro per aggiornamenti."""
        try:
            while True:
                item = self.worker_queue.get_nowait()
                if not item:
                    continue
                
                command = item[0]
                
                if command == 'progress':
                    current, total, message = item[1], item[2], item[3]
                    self.update_progress(current, total, message)
                
                elif command == 'results':
                    files = item[1]
                    self.update_results(files)
                
                elif command == 'success':
                    message = item[1]
                    self.status_var.set(message)
                    messagebox.showinfo("Operazione completata", message)
                
                elif command == 'error':
                    error_msg = item[1]
                    self.status_var.set(f"Errore: {error_msg}")
                    messagebox.showerror("Errore", error_msg)
                
                elif command == 'show_forensic_results':
                    results, files, algorithms = item[1], item[2], item[3]
                    self.show_forensic_results(results, files, algorithms)
                
                self.worker_queue.task_done()
        
        except queue.Empty:
            pass
        
        # Riavvia il timer
        self.root.after(100, self.check_worker_queue)

    def on_close(self):
        """Gestisce la chiusura dell'applicazione."""
        # Ferma tutti i thread in esecuzione
        self.stop_worker.set()
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(1.0)
        
        # Ferma la ricerca
        self.app.file_searcher.stop_search()
        
        # Chiudi l'applicazione
        self.root.quit()
        self.root.destroy()

class PyQtGUI:
    """Implementazione dell'interfaccia grafica con PyQt5."""
    
    def __init__(self, app):
        self.app = app
        if not HAS_QT:
            raise ImportError("PyQt5 non è installato")
        
        # Crea l'applicazione Qt
        self.qt_app = QtWidgets.QApplication([])
        
        # Crea la finestra principale
        self.window = QtWidgets.QMainWindow()
        self.window.setWindowTitle("Smart File Finder")
        self.window.setMinimumSize(800, 600)
        self.window.resize(1200, 800)
        
        # Widget centrale
        self.central_widget = QtWidgets.QWidget()
        self.window.setCentralWidget(self.central_widget)
        
        # Layout principale
        self.main_layout = QtWidgets.QVBoxLayout(self.central_widget)
        
        # Crea l'interfaccia
        self.create_menu()
        self.create_ui()
        
        # Configura thread separato per operazioni lunghe
        self.worker_queue = queue.Queue()
        self.stop_worker = threading.Event()
        self.worker_thread = None
        
        # Avvia il timer per controllare la coda di lavoro
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.check_worker_queue)
        self.timer.start(100)
    
    def create_menu(self):
        """Crea il menu dell'applicazione."""
        menubar = self.window.menuBar()
        
        # Menu File
        file_menu = menubar.addMenu("File")
        
        new_action = QtWidgets.QAction("Nuova ricerca", self.window)
        new_action.triggered.connect(self.reset_search)
        file_menu.addAction(new_action)
        
        file_menu.addSeparator()
        
        export_action = QtWidgets.QAction("Esporta risultati...", self.window)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        compress_action = QtWidgets.QAction("Comprimi file selezionati...", self.window)
        compress_action.triggered.connect(self.compress_selected)
        file_menu.addAction(compress_action)
        
        file_menu.addSeparator()
        
        exit_action = QtWidgets.QAction("Esci", self.window)
        exit_action.triggered.connect(self.window.close)
        file_menu.addAction(exit_action)
        
        # Menu Strumenti
        tools_menu = menubar.addMenu("Strumenti")
        
        forensic_action = QtWidgets.QAction("Analisi forense...", self.window)
        forensic_action.triggered.connect(self.forensic_analysis)
        tools_menu.addAction(forensic_action)
        
        ai_settings_action = QtWidgets.QAction("Impostazioni IA...", self.window)
        ai_settings_action.triggered.connect(self.show_ai_settings)
        tools_menu.addAction(ai_settings_action)
        
        tools_menu.addSeparator()
        
        admin_action = QtWidgets.QAction("Esegui come amministratore", self.window)
        admin_action.triggered.connect(self.app.permission_handler.elevate_privileges)
        tools_menu.addAction(admin_action)
        
        # Menu Aiuto
        help_menu = menubar.addMenu("Aiuto")
        
        help_action = QtWidgets.QAction("Guida", self.window)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
        
        about_action = QtWidgets.QAction("Informazioni", self.window)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_ui(self):
        """Crea l'interfaccia utente principale."""
        # Area superiore: controlli di ricerca
        search_group = QtWidgets.QGroupBox("Parametri di ricerca")
        search_layout = QtWidgets.QVBoxLayout(search_group)
        
        # Percorso di ricerca
        path_layout = QtWidgets.QHBoxLayout()
        path_layout.addWidget(QtWidgets.QLabel("Percorso:"))
        
        self.path_entry = QtWidgets.QLineEdit()
        self.path_entry.setText("")
        path_layout.addWidget(self.path_entry)
        
        browse_button = QtWidgets.QPushButton("Sfoglia...")
        browse_button.clicked.connect(self.browse_path)
        path_layout.addWidget(browse_button)
        
        search_layout.addLayout(path_layout)
        
        # Testo di ricerca
        text_layout = QtWidgets.QHBoxLayout()
        text_layout.addWidget(QtWidgets.QLabel("Testo da cercare:"))
        
        self.search_text_entry = QtWidgets.QLineEdit()
        text_layout.addWidget(self.search_text_entry)
        
        search_layout.addLayout(text_layout)
        
        # Opzioni di ricerca
        options_layout = QtWidgets.QHBoxLayout()
        
        # Estensioni
        ext_layout = QtWidgets.QHBoxLayout()
        ext_layout.addWidget(QtWidgets.QLabel("Estensioni:"))

        self.extensions_entry = QtWidgets.QLineEdit()
        self.extensions_entry.setText(".txt, .pdf, .doc, .docx")
        ext_layout.addWidget(self.extensions_entry)

        ext_button = QtWidgets.QPushButton("Scegli estensioni...")
        ext_button.clicked.connect(self.create_extension_selector_dialog)
        ext_layout.addWidget(ext_button)

        options_layout.addLayout(ext_layout)
        
        self.recursive_check = QtWidgets.QCheckBox("Ricerca ricorsiva")
        self.recursive_check.setChecked(True)
        options_layout.addWidget(self.recursive_check)
        
        options_layout.addWidget(QtWidgets.QLabel("Profondità max:"))
        
        self.max_depth_entry = QtWidgets.QLineEdit()
        self.max_depth_entry.setText("-1")
        self.max_depth_entry.setFixedWidth(50)
        options_layout.addWidget(self.max_depth_entry)
        
        search_button = QtWidgets.QPushButton("Avvia ricerca")
        search_button.clicked.connect(self.start_search)
        options_layout.addWidget(search_button)
        
        stop_button = QtWidgets.QPushButton("Ferma")
        stop_button.clicked.connect(self.stop_search)
        options_layout.addWidget(stop_button)
        
        search_layout.addLayout(options_layout)
        
        self.main_layout.addWidget(search_group)
        
        # Area centrale: risultati
        results_group = QtWidgets.QGroupBox("Risultati della ricerca")
        results_layout = QtWidgets.QVBoxLayout(results_group)
        
        # Tabella dei risultati
        self.results_table = QtWidgets.QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels(
            ["Nome", "Percorso", "Dimensione", "Categoria", "Ultima modifica", "Punteggio IA"]
        )
        self.results_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.results_table.doubleClicked.connect(self.show_file_details)
        self.results_table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Imposta le larghezze delle colonne
        self.results_table.setColumnWidth(0, 200)  # Nome
        self.results_table.setColumnWidth(1, 250)  # Percorso
        self.results_table.setColumnWidth(2, 100)  # Dimensione
        self.results_table.setColumnWidth(3, 120)  # Categoria
        self.results_table.setColumnWidth(4, 150)  # Ultima modifica
        self.results_table.setColumnWidth(5, 100)  # Punteggio IA
        
        results_layout.addWidget(self.results_table)
        
        self.main_layout.addWidget(results_group)
        
        # Area inferiore: anteprima e dettagli
        details_group = QtWidgets.QGroupBox("Dettagli file")
        details_layout = QtWidgets.QVBoxLayout(details_group)
        
        self.preview_text = QtWidgets.QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QtGui.QFont("Courier New", 10))
        details_layout.addWidget(self.preview_text)
        
        self.main_layout.addWidget(details_group)
        
        # Area di stato: barra di stato e progresso
        status_layout = QtWidgets.QVBoxLayout()
        
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        status_layout.addWidget(self.progress_bar)
        
        status_bar_layout = QtWidgets.QHBoxLayout()
        
        self.status_label = QtWidgets.QLabel("Pronto")
        status_bar_layout.addWidget(self.status_label)
        
        admin_text = "Admin" if self.app.permission_handler.is_admin() else "Utente standard"
        admin_label = QtWidgets.QLabel(admin_text)
        admin_label.setAlignment(QtCore.Qt.AlignRight)
        status_bar_layout.addWidget(admin_label)
        
        status_layout.addLayout(status_bar_layout)
        
        self.main_layout.addLayout(status_layout)
    
    def _select_all_extensions(self, category):
        """Seleziona tutte le estensioni di una categoria."""
        for key, checkbox in self.extension_checkboxes.items():
            if key[0] == category:
                checkbox.setChecked(True)

    def _deselect_all_extensions(self, category):
        """Deseleziona tutte le estensioni di una categoria."""
        for key, checkbox in self.extension_checkboxes.items():
            if key[0] == category:
                checkbox.setChecked(False)

    def _select_all_extensions_global(self):
        """Seleziona tutte le estensioni."""
        for checkbox in self.extension_checkboxes.values():
            checkbox.setChecked(True)

    def _deselect_all_extensions_global(self):
        """Deseleziona tutte le estensioni."""
        for checkbox in self.extension_checkboxes.values():
            checkbox.setChecked(False)

    def _apply_extension_selection(self, dialog):
        """Applica la selezione delle estensioni."""
        # Raccogli le estensioni selezionate
        selected_exts = []
        for ext, var in self.extension_vars.items():
            if var.get():
                selected_exts.append(ext)
        
        # Aggiungi le estensioni personalizzate
        custom_exts_text = self.custom_exts_var.get()
        if custom_exts_text:
            custom_exts = [ext.strip() for ext in custom_exts_text.split(',')]
            for ext in custom_exts:
                if not ext:
                    continue
                ext = ext if ext.startswith('.') else f'.{ext}'
                if ext not in selected_exts:
                    selected_exts.append(ext)
        
        # Imposta il valore nel campo delle estensioni
        self.extensions_var.set(", ".join(selected_exts))
        
        # Chiudi la finestra
        dialog.destroy()

    def browse_path(self):
        """Apre un dialogo per selezionare il percorso di ricerca."""
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self.window, "Seleziona directory", self.path_entry.text()
        )
        if directory:
            self.path_entry.setText(directory)
    
    def get_extensions_list(self) -> List[str]:
        """Converte la stringa delle estensioni in una lista."""
        extensions_text = self.extensions_entry.text().strip()
        if not extensions_text:
            return None  # Tutte le estensioni
        
        # Dividi la stringa per virgole e pulisci ogni elemento
        extensions = [ext.strip() for ext in extensions_text.split(',')]
        # Assicurati che ogni estensione inizi con un punto
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        return extensions
    
    def update_progress(self, current, total, message=None):
        """Aggiorna la barra di progresso e il messaggio di stato."""
        if total > 0:
            progress = (current / total) * 100
            self.progress_bar.setValue(int(progress))
        else:
            self.progress_bar.setValue(0)
        
        if message:
            self.status_label.setText(message)
    
    def start_search(self):
        """Avvia la ricerca dei file."""
        # Verifica che il percorso esista
        search_path = self.path_entry.text()
        if not os.path.exists(search_path):
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                          f"Il percorso '{search_path}' non esiste")
            return
        
        # Verifica i permessi
        if not self.app.permission_handler.has_permission(search_path):
            result = QtWidgets.QMessageBox.question(
                self.window, "Permessi insufficienti",
                "Non hai permessi sufficienti per accedere a questa cartella. "
                "Vuoi eseguire l'applicazione come amministratore?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            if result == QtWidgets.QMessageBox.Yes:
                self.app.permission_handler.elevate_privileges()
                return
        
        # Ottieni gli altri parametri
        search_text = self.search_text_entry.text()
        extensions = self.get_extensions_list()
        recursive = self.recursive_check.isChecked()
        
        try:
            max_depth = int(self.max_depth_entry.text())
        except ValueError:
            max_depth = -1  # Valore predefinito
        
        # Cancella i risultati precedenti
        self.results_table.setRowCount(0)
        
        # Reimposta la barra di progresso
        self.progress_bar.setValue(0)
        self.status_label.setText("Avvio della ricerca...")
        
        # Avvia la ricerca in un thread separato
        self.search_params = {
            'start_paths': [search_path],
            'search_text': search_text,
            'extensions': extensions,
            'max_depth': max_depth,
            'recursive': recursive
        }
        
        self.launch_worker(self._search_worker)
    
    def _search_worker(self):
        """Thread worker per la ricerca dei file."""
        try:
            # Imposta il callback di progresso
            self.app.file_searcher.set_progress_callback(
                lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
            )
            
            # Avvia la ricerca
            results = self.app.file_searcher.search_files(**self.search_params)
            
            # Invia i risultati alla coda
            self.worker_queue.put(('results', results))
            
        except Exception as e:
            self.worker_queue.put(('error', str(e)))
    
    def update_results(self, files: List[FileInfo]):
        """Aggiorna la tabella dei risultati con i file trovati."""
        # Cancella i risultati precedenti
        self.results_table.setRowCount(0)
        
        # Aggiungi i nuovi risultati
        for i, file_info in enumerate(files):
            self.results_table.insertRow(i)
            
            # Nome file
            self.results_table.setItem(i, 0, QtWidgets.QTableWidgetItem(file_info.name))
            
            # Percorso
            self.results_table.setItem(i, 1, QtWidgets.QTableWidgetItem(file_info.path))
            
            # Dimensione
            self.results_table.setItem(i, 2, QtWidgets.QTableWidgetItem(file_info.get_formatted_size()))
            
            # Categoria
            self.results_table.setItem(i, 3, QtWidgets.QTableWidgetItem(file_info.category.value))
            
            # Ultima modifica
            self.results_table.setItem(i, 4, QtWidgets.QTableWidgetItem(
                file_info.get_formatted_date(file_info.last_modified)))
            
            # Punteggio IA
            self.results_table.setItem(i, 5, QtWidgets.QTableWidgetItem(
                f"{file_info.ai_score:.2f}" if file_info.ai_score > 0 else "-"))
            
            # Memorizza il percorso completo come dato utente
            for col in range(6):
                self.results_table.item(i, col).setData(QtCore.Qt.UserRole, file_info.full_path())
    
    def stop_search(self):
        """Ferma la ricerca in corso."""
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_worker.set()
            self.app.file_searcher.stop_search()
            self.status_label.setText("Interruzione della ricerca...")
    
    def show_file_details(self, index):
        """Mostra i dettagli di un file selezionato."""
        row = index.row()
        if row < 0:
            return
        
        # Ottieni il percorso del file dai dati utente
        file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
        if not os.path.exists(file_path):
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                         f"Il file '{file_path}' non esiste più")
            return
        
        # Crea un oggetto FileInfo per il file
        path, name = os.path.split(file_path)
        size = os.path.getsize(file_path)
        file_info = FileInfo(path, name, size)
        
        # Genera l'anteprima
        preview = file_info.generate_preview()
        
        # Aggiorna l'area di anteprima
        self.preview_text.setPlainText(preview)
    
    def show_context_menu(self, position):
        """Mostra il menu contestuale per un elemento selezionato."""
        index = self.results_table.indexAt(position)
        if not index.isValid():
            return
        
        # Crea il menu contestuale
        context_menu = QtWidgets.QMenu()
        open_action = context_menu.addAction("Apri")
        open_folder_action = context_menu.addAction("Apri cartella")
        context_menu.addSeparator()
        forensic_action = context_menu.addAction("Analisi forense")
        context_menu.addSeparator()
        copy_path_action = context_menu.addAction("Copia percorso")
        
        # Mostra il menu e ottieni l'azione selezionata
        action = context_menu.exec_(self.results_table.mapToGlobal(position))
        
        if action == open_action:
            self.open_selected_file()
        elif action == open_folder_action:
            self.open_selected_folder()
        elif action == forensic_action:
            self.forensic_analysis([index.row()])
        elif action == copy_path_action:
            self.copy_path_to_clipboard()
    
    def open_selected_file(self):
        """Apre il file selezionato con l'applicazione predefinita."""
        indexes = self.results_table.selectedIndexes()
        if not indexes:
            return
        
        row = indexes[0].row()
        file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
        if not os.path.exists(file_path):
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                         f"Il file '{file_path}' non esiste più")
            return
        
        # Apri il file con l'applicazione predefinita
        try:
            if sys.platform == 'win32':
                os.startfile(file_path)
            elif sys.platform == 'darwin':
                os.system(f'open "{file_path}"')
            else:
                os.system(f'xdg-open "{file_path}"')
        except Exception as e:
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                         f"Impossibile aprire il file: {str(e)}")
    
    def open_selected_folder(self):
        """Apre la cartella contenente il file selezionato."""
        indexes = self.results_table.selectedIndexes()
        if not indexes:
            return
        
        row = indexes[0].row()
        file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
        folder_path = os.path.dirname(file_path)
        
        if not os.path.exists(folder_path):
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                         f"La cartella '{folder_path}' non esiste più")
            return
        
        # Apri la cartella con l'applicazione predefinita
        try:
            if sys.platform == 'win32':
                os.startfile(folder_path)
            elif sys.platform == 'darwin':
                os.system(f'open "{folder_path}"')
            else:
                os.system(f'xdg-open "{folder_path}"')
        except Exception as e:
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                         f"Impossibile aprire la cartella: {str(e)}")
    
    def copy_path_to_clipboard(self):
        """Copia il percorso del file selezionato negli appunti."""
        indexes = self.results_table.selectedIndexes()
        if not indexes:
            return
        
        row = indexes[0].row()
        file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
        
        # Copia negli appunti
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(file_path)
        self.status_label.setText(f"Percorso copiato: {file_path}")
    
    def reset_search(self):
        """Reimposta i parametri di ricerca."""
        self.search_text_entry.setText("")
        self.extensions_entry.setText(".txt, .pdf, .doc, .docx")
        self.recursive_check.setChecked(True)
        self.max_depth_entry.setText("-1")
        
        # Cancella i risultati
        self.results_table.setRowCount(0)
        
        # Reimposta la barra di progresso
        self.progress_bar.setValue(0)
        self.status_label.setText("Pronto")
    
    def export_results(self):
        """Esporta i risultati della ricerca in un file JSON."""
        # Verifica se ci sono risultati
        if self.results_table.rowCount() == 0:
            QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                           "Non ci sono risultati da esportare")
            return
        
        # Chiedi il nome del file
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.window, "Esporta risultati", "", "File JSON (*.json);;Tutti i file (*.*)"
        )
        
        if not file_path:
            return
        
        # Raccolta i dati
        results = []
        for row in range(self.results_table.rowCount()):
            file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
            path, name = os.path.split(file_path)
            
            try:
                size = os.path.getsize(file_path)
                file_info = FileInfo(path, name, size)
                results.append(file_info.to_dict())
            except (FileNotFoundError, PermissionError):
                # Ignora i file che non esistono più o non sono accessibili
                pass
        
        # Esporta i dati
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'export_date': datetime.datetime.now().isoformat(),
                    'file_count': len(results),
                    'files': results
                }, f, indent=2)
            
            self.status_label.setText(f"Risultati esportati in {file_path}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                        f"Impossibile esportare i risultati: {str(e)}")
    
    def compress_selected(self):
        """Comprime i file selezionati."""
        # Ottieni i file selezionati
        rows = set(index.row() for index in self.results_table.selectedIndexes())
        if not rows:
            QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                           "Nessun file selezionato")
            return
        
        # Chiedi il nome del file di output
        output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.window, "Comprimi file", "", "File ZIP (*.zip);;Tutti i file (*.*)"
        )
        
        if not output_path:
            return
        
        # Raccogli i dati dei file
        files_to_compress = []
        for row in rows:
            file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
            if not os.path.exists(file_path):
                continue
            
            path, name = os.path.split(file_path)
            size = os.path.getsize(file_path)
            file_info = FileInfo(path, name, size)
            files_to_compress.append(file_info)
        
        if not files_to_compress:
            QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                           "Nessun file valido selezionato")
            return
        
        # Imposta il callback di progresso
        self.app.compression_engine.set_progress_callback(
            lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
        )
        
        # Avvia la compressione in un thread separato
        self.launch_worker(lambda: self._compress_worker(files_to_compress, output_path))
    
    def _compress_worker(self, files, output_path):
        """Thread worker per la compressione dei file."""
        try:
            result = self.app.compression_engine.compress_files(files, output_path)
            if result:
                self.worker_queue.put(('success', f"File compressi in {result}"))
            else:
                self.worker_queue.put(('error', "Errore nella compressione dei file"))
        except Exception as e:
            self.worker_queue.put(('error', str(e)))
    
    def forensic_analysis(self, selected_rows=None):
        """Esegue l'analisi forense dei file selezionati."""
        # Se non sono stati specificati ID, usa la selezione corrente
        if selected_rows is None:
            selected_rows = [index.row() for index in self.results_table.selectedIndexes()]
            selected_rows = list(set(selected_rows))  # Rimuovi duplicati
        
        if not selected_rows:
            QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                           "Nessun file selezionato")
            return
        
        # Crea una finestra di dialogo per le opzioni forensi
        dialog = QtWidgets.QDialog(self.window)
        dialog.setWindowTitle("Analisi forense")
        dialog.setMinimumSize(300, 200)
        
        layout = QtWidgets.QVBoxLayout(dialog)
        
        # Algoritmi
        algo_group = QtWidgets.QGroupBox("Algoritmi di hash")
        algo_layout = QtWidgets.QVBoxLayout(algo_group)
        
        md5_check = QtWidgets.QCheckBox("MD5")
        md5_check.setChecked(True)
        algo_layout.addWidget(md5_check)
        
        sha1_check = QtWidgets.QCheckBox("SHA-1")
        algo_layout.addWidget(sha1_check)
        
        sha256_check = QtWidgets.QCheckBox("SHA-256")
        sha256_check.setChecked(True)
        algo_layout.addWidget(sha256_check)
        
        sha512_check = QtWidgets.QCheckBox("SHA-512")
        algo_layout.addWidget(sha512_check)
        
        layout.addWidget(algo_group)
        
        # Opzioni report
        report_group = QtWidgets.QGroupBox("Opzioni report")
        report_layout = QtWidgets.QVBoxLayout(report_group)
        
        create_report_check = QtWidgets.QCheckBox("Crea report")
        create_report_check.setChecked(True)
        report_layout.addWidget(create_report_check)
        
        layout.addWidget(report_group)
        
        # Pulsanti
        button_layout = QtWidgets.QHBoxLayout()
        
        cancel_button = QtWidgets.QPushButton("Annulla")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        analyze_button = QtWidgets.QPushButton("Analizza")
        analyze_button.clicked.connect(dialog.accept)
        button_layout.addWidget(analyze_button)
        
        layout.addLayout(button_layout)
        
        # Mostra la finestra di dialogo
        if dialog.exec_() != QtWidgets.QDialog.Accepted:
            return
        
        # Raccogli gli algoritmi selezionati
        algorithms = []
        if md5_check.isChecked():
            algorithms.append(ForensicAlgorithm.MD5)
        if sha1_check.isChecked():
            algorithms.append(ForensicAlgorithm.SHA1)
        if sha256_check.isChecked():
            algorithms.append(ForensicAlgorithm.SHA256)
        if sha512_check.isChecked():
            algorithms.append(ForensicAlgorithm.SHA512)
        
        if not algorithms:
            QtWidgets.QMessageBox.warning(self.window, "Attenzione", 
                                         "Seleziona almeno un algoritmo")
            return
        
        # Raccogli i dati dei file
        files_to_analyze = []
        for row in selected_rows:
            file_path = self.results_table.item(row, 0).data(QtCore.Qt.UserRole)
            if not os.path.exists(file_path):
                continue
            
            path, name = os.path.split(file_path)
            size = os.path.getsize(file_path)
            file_info = FileInfo(path, name, size)
            files_to_analyze.append(file_info)
        
        if not files_to_analyze:
            QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                           "Nessun file valido selezionato")
            return
        
        # Se l'utente vuole creare un report, chiedi il percorso
        report_path = None
        if create_report_check.isChecked():
            report_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self.window, "Salva report forense", "", "File JSON (*.json);;Tutti i file (*.*)"
            )
            
            if not report_path:
                QtWidgets.QMessageBox.information(self.window, "Informazione", 
                                               "Analisi forense annullata")
                return
        
        # Imposta il callback di progresso
        self.app.forensic_engine.set_progress_callback(
            lambda current, total, msg: self.worker_queue.put(('progress', current, total, msg))
        )
        
        # Avvia l'analisi in un thread separato
        self.launch_worker(lambda: self._forensic_worker(files_to_analyze, algorithms, report_path))
    
    def _forensic_worker(self, files, algorithms, report_path=None):
        """Thread worker per l'analisi forense."""
        try:
            # Esegui l'analisi
            results = self.app.forensic_engine.analyze_files(files, algorithms)
            
            # Crea il report se richiesto
            if report_path:
                self.app.forensic_engine.export_report(files, algorithms, report_path)
                self.worker_queue.put(('success', f"Report forense salvato in {report_path}"))
            
            # Prepara il messaggio con i risultati
            file_count = len(files)
            algo_count = len(algorithms)
            self.worker_queue.put(('success', f"Analisi forense completata per {file_count} file con {algo_count} algoritmi"))
            
            # Mostra i risultati in una nuova finestra
            self.worker_queue.put(('show_forensic_results', results, files, algorithms))
            
        except Exception as e:
            self.worker_queue.put(('error', str(e)))
    
    def show_forensic_results(self, results, files, algorithms):
        """Mostra i risultati dell'analisi forense in una finestra separata."""
        # Crea una nuova finestra
        result_dialog = QtWidgets.QDialog(self.window)
        result_dialog.setWindowTitle("Risultati Analisi Forense")
        result_dialog.resize(800, 600)
        
        layout = QtWidgets.QVBoxLayout(result_dialog)
        
        # Crea una tabella per i risultati
        result_table = QtWidgets.QTableWidget()
        
        # Imposta le colonne
        columns = ['file', 'path']
        for algo in algorithms:
            columns.append(algo.value)
        
        result_table.setColumnCount(len(columns))
        result_table.setHorizontalHeaderLabels(['Nome file', 'Percorso'] + 
                                              [algo.value for algo in algorithms])
        
        # Imposta le larghezze delle colonne
        result_table.setColumnWidth(0, 150)  # Nome file
        result_table.setColumnWidth(1, 250)  # Percorso
        for i in range(2, len(columns)):
            result_table.setColumnWidth(i, 150)  # Algoritmi
        
        # Aggiungi i risultati alla tabella
        result_table.setRowCount(len(files))
        for i, file_info in enumerate(files):
            file_path = file_info.full_path()
            if file_path in results:
                # Nome file
                result_table.setItem(i, 0, QtWidgets.QTableWidgetItem(file_info.name))
                
                # Percorso
                result_table.setItem(i, 1, QtWidgets.QTableWidgetItem(file_info.path))
                
                # Hash per ogni algoritmo
                for j, algo in enumerate(algorithms):
                    if algo.value in results[file_path]:
                        result_table.setItem(i, j + 2, 
                                           QtWidgets.QTableWidgetItem(results[file_path][algo.value]))
                    else:
                        result_table.setItem(i, j + 2, QtWidgets.QTableWidgetItem("-"))
        
        layout.addWidget(result_table)
        
        # Pulsanti di azione
        button_layout = QtWidgets.QHBoxLayout()
        
        close_button = QtWidgets.QPushButton("Chiudi")
        close_button.clicked.connect(result_dialog.accept)
        button_layout.addWidget(close_button)
        
        export_button = QtWidgets.QPushButton("Esporta CSV...")
        export_button.clicked.connect(lambda: self._export_forensic_csv(results, files, algorithms))
        button_layout.addWidget(export_button)
        
        layout.addLayout(button_layout)
        
        # Mostra la finestra
        result_dialog.exec_()
    
    def _export_forensic_csv(self, results, files, algorithms):
        """Esporta i risultati dell'analisi forense in un file CSV."""
        # Chiedi il percorso del file
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self.window, "Esporta risultati", "", "File CSV (*.csv);;Tutti i file (*.*)"
        )
        
        if not file_path:
            return
        
        try:
            import csv
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Crea l'intestazione
                fieldnames = ['Nome file', 'Percorso']
                for algo in algorithms:
                    fieldnames.append(algo.value)
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Scrivi i dati
                for file_info in files:
                    file_path = file_info.full_path()
                    if file_path in results:
                        row = {
                            'Nome file': file_info.name,
                            'Percorso': file_info.path
                        }
                        for algo in algorithms:
                            if algo.value in results[file_path]:
                                row[algo.value] = results[file_path][algo.value]
                            else:
                                row[algo.value] = ""
                        writer.writerow(row)
            
            self.status_label.setText(f"Risultati forensi esportati in CSV")
            
        except Exception as e:
            QtWidgets.QMessageBox.critical(self.window, "Errore", 
                                        f"Impossibile esportare i risultati: {str(e)}")
    
    def show_ai_settings(self):
        """Mostra le impostazioni dell'IA."""
        dialog = QtWidgets.QDialog(self.window)
        dialog.setWindowTitle("Impostazioni IA")
        dialog.setMinimumSize(400, 300)
        
        layout = QtWidgets.QVBoxLayout(dialog)
        
        # Informazioni sulle librerie
        info_group = QtWidgets.QGroupBox("Stato librerie IA")
        info_layout = QtWidgets.QVBoxLayout(info_group)
        
        # Verifica lo stato delle librerie
        ai_status = "Installate e operative" if HAS_AI_LIBS else "Non disponibili"
        info_layout.addWidget(QtWidgets.QLabel(f"Librerie IA: {ai_status}"))
        
        # Elenca le librerie
        libraries = [
            ("NumPy", "numpy"),
            ("Scikit-learn", "sklearn"),
            ("NLTK", "nltk")
        ]
        
        for name, module in libraries:
            try:
                __import__(module)
                status = "✓ Installata"
            except ImportError:
                status = "✗ Non installata"
            info_layout.addWidget(QtWidgets.QLabel(f"{name}: {status}"))
        
        layout.addWidget(info_group)
        
        # Impostazioni di soglia
        settings_group = QtWidgets.QGroupBox("Impostazioni di soglia")
        settings_layout = QtWidgets.QVBoxLayout(settings_group)
        
        settings_layout.addWidget(QtWidgets.QLabel("Soglia di rilevanza (0.0-1.0):"))
        
        # Imposta il valore attuale
        threshold_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        threshold_slider.setRange(0, 100)
        threshold_slider.setValue(int(self.app.ai_engine.threshold * 100))
        settings_layout.addWidget(threshold_slider)
        
        # Etichetta del valore attuale
        threshold_label = QtWidgets.QLabel(f"{self.app.ai_engine.threshold:.2f}")
        threshold_label.setAlignment(QtCore.Qt.AlignRight)
        settings_layout.addWidget(threshold_label)
        
        # Aggiorna l'etichetta quando il valore cambia
        def update_threshold_label(value):
            threshold_label.setText(f"{value / 100:.2f}")
        
        threshold_slider.valueChanged.connect(update_threshold_label)
        
        layout.addWidget(settings_group)
        
        # Pulsanti
        button_layout = QtWidgets.QHBoxLayout()
        
        cancel_button = QtWidgets.QPushButton("Annulla")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)
        
        apply_button = QtWidgets.QPushButton("Applica")
        apply_button.clicked.connect(lambda: self._apply_ai_settings(threshold_slider.value() / 100, dialog))
        button_layout.addWidget(apply_button)
        
        layout.addLayout(button_layout)
        
        # Mostra la finestra
        dialog.exec_()
    
    def _apply_ai_settings(self, threshold, dialog):
        """Applica le nuove impostazioni dell'IA."""
        # Aggiorna la soglia
        self.app.ai_engine.threshold = threshold
        
        # Chiudi la finestra
        dialog.accept()
        
        # Aggiorna lo stato
        self.status_label.setText(f"Impostazioni IA aggiornate: soglia di rilevanza = {threshold:.2f}")
    
    def show_help(self):
        """Mostra la guida dell'applicazione."""
        help_dialog = QtWidgets.QDialog(self.window)
        help_dialog.setWindowTitle("Guida - Smart File Finder")
        help_dialog.resize(700, 500)
        help_dialog.setMinimumSize(600, 400)
        
        layout = QtWidgets.QVBoxLayout(help_dialog)
        
        # Area di testo per la guida
        help_text = QtWidgets.QTextEdit()
        help_text.setReadOnly(True)
        help_text.setFont(QtGui.QFont("Segoe UI", 10))
        
        # Contenuto della guida
        guide = """# Guida a Smart File Finder

    ## Introduzione
    Smart File Finder è un'applicazione avanzata per la ricerca di file che utilizza l'intelligenza artificiale per trovare, categorizzare e analizzare i file sul tuo sistema.

    ## Funzionalità principali

    ### Ricerca di file
    1. Inserisci il percorso in cui cercare o usa "Sfoglia..." per selezionarlo.
    2. Inserisci il testo da cercare nei nomi dei file.
    3. Specifica le estensioni di file da includere (separate da virgole).
    4. Scegli se la ricerca deve essere ricorsiva e la profondità massima.
    5. Clicca su "Avvia ricerca" per iniziare.

    ### Risultati della ricerca
    - I risultati vengono visualizzati nella tabella centrale.
    - Fai doppio clic su un file per visualizzarne l'anteprima.
    - Usa il menu contestuale (clic destro) per ulteriori opzioni.

    ### Compressione
    - Seleziona uno o più file nei risultati.
    - Scegli "Comprimi file selezionati..." dal menu File.
    - Seleziona il percorso di output per l'archivio ZIP.

    ### Analisi forense
    - Seleziona uno o più file nei risultati.
    - Scegli "Analisi forense..." dal menu Strumenti.
    - Seleziona gli algoritmi di hash da utilizzare.
    - Visualizza o esporta i risultati.

    ## Suggerimenti
    - Per una ricerca più precisa, utilizza parole chiave specifiche.
    - L'IA migliorerà la rilevanza dei risultati in base al contenuto dei file.
    - Per accedere a cartelle protette, esegui l'applicazione come amministratore.

    ## Requisiti
    - Python 3.6 o superiore
    - Librerie: numpy, scikit-learn, nltk (opzionali per funzionalità IA avanzate)

    ## Supporto
    Per problemi o suggerimenti, contatta il supporto tecnico.
    """
        
        # Inserisci il testo della guida
        help_text.setPlainText(guide)
        layout.addWidget(help_text)
        
        # Pulsante di chiusura
        close_button = QtWidgets.QPushButton("Chiudi")
        close_button.clicked.connect(help_dialog.accept)
        layout.addWidget(close_button)
        
        # Mostra la finestra
        help_dialog.exec_()

    def show_about(self):
        """Mostra informazioni sull'applicazione."""
        QtWidgets.QMessageBox.about(
            self.window,
            "Informazioni su Smart File Finder",
            "Smart File Finder v1.0\n\n"
            "Un'applicazione avanzata per la ricerca di file con IA.\n\n"
            "Caratteristiche:\n"
            "- Ricerca intelligente di file\n"
            "- Categorizzazione automatica\n"
            "- Compressione integrata\n"
            "- Analisi forense\n\n"
            "Sviluppato per Nino19980\n"
            f"Data: {datetime.datetime.now().strftime('%Y-%m-%d')}"
        )

    def launch_worker(self, worker_func):
        """Avvia un thread worker per operazioni lunghe."""
        # Ferma il thread precedente se è in esecuzione
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_worker.set()
            self.worker_thread.join(1.0)
        
        # Reimposta il flag di stop
        self.stop_worker.clear()
        
        # Avvia il nuovo thread
        self.worker_thread = threading.Thread(target=worker_func)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def check_worker_queue(self):
        """Controlla la coda di lavoro per aggiornamenti."""
        try:
            while True:
                item = self.worker_queue.get_nowait()
                if not item:
                    continue
                
                command = item[0]
                
                if command == 'progress':
                    current, total, message = item[1], item[2], item[3]
                    self.update_progress(current, total, message)
                
                elif command == 'results':
                    files = item[1]
                    self.update_results(files)
                
                elif command == 'success':
                    message = item[1]
                    self.status_label.setText(message)
                    QtWidgets.QMessageBox.information(self.window, "Operazione completata", message)
                
                elif command == 'error':
                    error_msg = item[1]
                    self.status_label.setText(f"Errore: {error_msg}")
                    QtWidgets.QMessageBox.critical(self.window, "Errore", error_msg)
                
                elif command == 'show_forensic_results':
                    results, files, algorithms = item[1], item[2], item[3]
                    self.show_forensic_results(results, files, algorithms)
                
                self.worker_queue.task_done()
        
        except queue.Empty:
            pass
        
        # Riavvia il timer
        self.timer.start(100)

    def run(self):
        """Avvia l'interfaccia grafica."""
        self.window.show()
        self.qt_app.exec_()


class SmartFileFinder:
    """Applicazione principale."""
    
    def __init__(self):
        # Inizializzazione dei componenti
        self.ai_engine = AIEngine()
        self.file_searcher = FileSearcher(self.ai_engine)
        self.compression_engine = CompressionEngine()
        self.forensic_engine = ForensicEngine()
        self.permission_handler = PermissionHandler()
        
        # Inizializzazione dell'interfaccia grafica
        if HAS_TK:
            self.gui = TkinterGUI(self)
        elif HAS_QT:
            self.gui = PyQtGUI(self)
        else:
            raise ImportError("Nessuna libreria GUI disponibile")
    
    def run(self):
        """Avvia l'applicazione."""
        # Verifica se mancano librerie importanti
        if not HAS_AI_LIBS:
            if HAS_TK:
                tk.messagebox.showwarning(
                    "Librerie mancanti",
                    "Alcune librerie di IA non sono disponibili. "
                    "Le funzionalità di intelligenza artificiale saranno limitate.\n\n"
                    "Per installare le librerie necessarie:\n"
                    "pip install numpy scikit-learn nltk"
                )
            elif HAS_QT:
                QtWidgets.QMessageBox.warning(
                    None,
                    "Librerie mancanti",
                    "Alcune librerie di IA non sono disponibili. "
                    "Le funzionalità di intelligenza artificiale saranno limitate.\n\n"
                    "Per installare le librerie necessarie:\n"
                    "pip install numpy scikit-learn nltk"
                )
        
        # Avvia l'interfaccia grafica
        if HAS_TK:
            self.gui.root.mainloop()
        elif HAS_QT:
            self.gui.run()


def main():
    """Funzione principale."""
    try:
        app = SmartFileFinder()
        app.run()
    except Exception as e:
        error_message = f"Errore imprevisto: {str(e)}\n\n{traceback.format_exc()}"
        
        if HAS_TK:
            try:
                import tkinter.messagebox
                tkinter.messagebox.showerror("Errore fatale", error_message)
            except:
                print(error_message)
        elif HAS_QT:
            try:
                from PyQt5.QtWidgets import QApplication, QMessageBox
                app = QApplication([])
                QMessageBox.critical(None, "Errore fatale", error_message)
            except:
                print(error_message)
        else:
            print(error_message)
        
        sys.exit(1)


if __name__ == "__main__":
    main()
