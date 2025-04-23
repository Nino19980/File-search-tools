import os
import sys
import hashlib
import zipfile
import threading
import queue
import time
import magic
import mimetypes
import re
import pickle
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import joblib
from concurrent.futures import ThreadPoolExecutor
import logging
import ctypes
import platform

# Configurazione logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("ai_file_finder.log"), logging.StreamHandler()]
)
logger = logging.getLogger("AI_FileFinder")

class FileDatabase:
    """Gestisce l'archiviazione e l'indicizzazione dei file per la ricerca rapida"""
    
    def __init__(self, db_path="file_database.pkl"):
        self.db_path = db_path
        self.files_index = {}
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.load_database()
        
    def load_database(self):
        """Carica il database esistente se disponibile"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'rb') as f:
                    data = pickle.load(f)
                    self.files_index = data.get('index', {})
                    self.vectorizer = data.get('vectorizer', TfidfVectorizer(stop_words='english'))
                logger.info(f"Database caricato con {len(self.files_index)} elementi")
            else:
                logger.info("Nessun database esistente trovato. Creazione di un nuovo database.")
        except Exception as e:
            logger.error(f"Errore nel caricamento del database: {e}")
            self.files_index = {}
    
    def save_database(self):
        """Salva il database su disco"""
        try:
            with open(self.db_path, 'wb') as f:
                pickle.dump({
                    'index': self.files_index,
                    'vectorizer': self.vectorizer
                }, f)
            logger.info(f"Database salvato con {len(self.files_index)} elementi")
        except Exception as e:
            logger.error(f"Errore nel salvataggio del database: {e}")
    
    def add_file(self, file_path, content_preview, category, file_size, last_modified):
        """Aggiunge un file al database"""
        self.files_index[file_path] = {
            'content_preview': content_preview,
            'category': category,
            'size': file_size,
            'last_modified': last_modified,
            'indexed_time': time.time()
        }
    
    def search(self, query, categories=None, extensions=None, max_results=100):
        """Ricerca file nel database utilizzando NLP"""
        if not self.files_index:
            return []
            
        # Prepara i dati per la ricerca vettoriale
        documents = []
        file_paths = []
        
        for path, info in self.files_index.items():
            # Filtra per categoria se specificato
            if categories and info['category'] not in categories:
                continue
                
            # Filtra per estensione se specificato
            if extensions:
                _, ext = os.path.splitext(path)
                if ext.lower() not in [e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions]:
                    continue
                    
            documents.append(info['content_preview'])
            file_paths.append(path)
        
        if not documents:
            return []
            
        # Calcola la similarità con la query
        try:
            tfidf_matrix = self.vectorizer.fit_transform(documents)
            query_vec = self.vectorizer.transform([query])
            cosine_similarities = cosine_similarity(query_vec, tfidf_matrix).flatten()
            
            # Ordina i risultati per rilevanza
            results_with_scores = sorted(
                [(file_paths[i], cosine_similarities[i]) for i in range(len(file_paths))],
                key=lambda x: x[1], 
                reverse=True
            )
            
            # Filtra per score minimo e limita i risultati
            return [(path, score) for path, score in results_with_scores if score > 0.1][:max_results]
        except Exception as e:
            logger.error(f"Errore nella ricerca: {e}")
            return []


class FileCategorizer:
    """Categorizza i file in base al tipo e al contenuto"""
    
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        
    def categorize(self, file_path):
        """Determina la categoria di un file basandosi su tipo MIME e altre caratteristiche"""
        try:
            # Ottieni estensione e MIME type
            _, ext = os.path.splitext(file_path)
            ext = ext.lower()
            
            # Usa magic per determinare il MIME type
            try:
                mime_type = self.mime.from_file(file_path)
            except:
                mime_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
            
            # Categorizzazione basata su tipo MIME e estensione
            if mime_type.startswith('image/'):
                return "Immagini"
            elif mime_type.startswith('video/'):
                return "Video"
            elif mime_type.startswith('audio/'):
                return "Audio"
            elif mime_type.startswith('text/'):
                if ext in ['.py', '.java', '.cpp', '.c', '.h', '.js', '.php', '.rb', '.go', '.cs']:
                    return "Codice"
                elif ext in ['.txt', '.md', '.rtf', '.log']:
                    return "Testo"
                elif ext in ['.html', '.htm', '.xml', '.css']:
                    return "Web"
                else:
                    return "Documenti"
            elif "pdf" in mime_type:
                return "Documenti"
            elif ext in ['.doc', '.docx', '.odt', '.rtf']:
                return "Documenti"
            elif ext in ['.xls', '.xlsx', '.ods', '.csv']:
                return "Fogli di calcolo"
            elif ext in ['.ppt', '.pptx', '.odp']:
                return "Presentazioni"
            elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
                return "Archivi"
            elif ext in ['.exe', '.msi', '.bin', '.app', '.dmg', '.sh', '.bat']:
                return "Eseguibili"
            elif ext in ['.db', '.sqlite', '.sqlite3', '.sql']:
                return "Database"
            else:
                return "Altri"
        except Exception as e:
            logger.error(f"Errore nella categorizzazione di {file_path}: {e}")
            return "Non categorizzato"


class FileHasher:
    """Calcola hash forensi per i file"""
    
    @staticmethod
    def calculate_hash(file_path, algorithms=None):
        """Calcola gli hash di un file usando gli algoritmi specificati"""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
            
        hashes = {}
        
        try:
            for algorithm in algorithms:
                hasher = getattr(hashlib, algorithm)()
                
                with open(file_path, 'rb') as f:
                    # Leggi il file a blocchi per gestire file di grandi dimensioni
                    for chunk in iter(lambda: f.read(4096), b''):
                        hasher.update(chunk)
                        
                hashes[algorithm] = hasher.hexdigest()
                
            return hashes
        except Exception as e:
            logger.error(f"Errore nel calcolo dell'hash per {file_path}: {e}")
            return {algo: "Errore" for algo in algorithms}


class FileCompressor:
    """Gestisce la compressione dei file"""
    
    @staticmethod
    def compress_files(files, output_path, compression_type='zip'):
        """Comprime una lista di file"""
        try:
            if compression_type == 'zip':
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file in files:
                        try:
                            zipf.write(file, os.path.basename(file))
                        except Exception as e:
                            logger.error(f"Errore nell'aggiunta del file {file} all'archivio: {e}")
                            
                return output_path
            else:
                logger.error(f"Tipo di compressione non supportato: {compression_type}")
                return None
        except Exception as e:
            logger.error(f"Errore nella compressione dei file: {e}")
            return None


class FileScanner:
    """Scansiona i filesystem per trovare e indicizzare i file"""
    
    def __init__(self, database, categorizer):
        self.database = database
        self.categorizer = categorizer
        self.stop_event = threading.Event()
        self.progress_queue = queue.Queue()
        self.extensions_filter = None
        self.max_files_per_batch = 1000  # Limita il numero di file elaborati per batch
        
    def set_extensions_filter(self, extensions):
        """Imposta il filtro delle estensioni"""
        if extensions and len(extensions) > 0:
            self.extensions_filter = [e.lower() if e.startswith('.') else f'.{e.lower()}' for e in extensions]
        else:
            self.extensions_filter = None
    
    def _check_path_access(self, path):
        """Verifica se il percorso è accessibile"""
        try:
            # Prova ad accedere alla directory
            os.listdir(path)
            return True
        except PermissionError:
            # Tenta di ottenere privilegi elevati su Windows
            if platform.system() == 'Windows':
                try:
                    if not ctypes.windll.shell32.IsUserAnAdmin():
                        logger.info("Tentativo di ottenere privilegi di amministratore")
                        # Questa funzione riavvierà il processo con privilegi elevati
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                except:
                    logger.error("Impossibile ottenere privilegi di amministratore")
            return False
        except Exception as e:
            logger.error(f"Errore nell'accesso al percorso {path}: {e}")
            return False
            
    def scan_directory(self, root_path, recursive=True, status_callback=None):
        """Scansiona una directory alla ricerca di file"""
        self.stop_event.clear()
        total_files = 0
        indexed_files = 0
        files_to_process = []
        
        try:
            # Ottiene i permessi di amministratore se necessario
            if not self._check_path_access(root_path):
                logger.warning(f"Accesso limitato al percorso {root_path}. Alcuni file potrebbero non essere accessibili.")
                if status_callback:
                    self.progress_queue.put((0, 0, "Accesso limitato al percorso. Alcuni file potrebbero non essere accessibili."))
            
            # Funzione per processare un singolo file
            def process_file(file_path):
                nonlocal indexed_files
                try:
                    # Filtra per estensione se necessario
                    if self.extensions_filter:
                        _, ext = os.path.splitext(file_path)
                        if ext.lower() not in self.extensions_filter:
                            return
                    
                    # Verifica che il file sia accessibile prima di procedere
                    if not os.access(file_path, os.R_OK):
                        logger.warning(f"File non accessibile: {file_path}")
                        return
                    
                    # Ottieni metadati del file
                    stats = os.stat(file_path)
                    size = stats.st_size
                    modified = stats.st_mtime
                    
                    # Ottieni un'anteprima del contenuto per l'indicizzazione
                    content_preview = self._get_file_preview(file_path)
                    
                    # Categorizza il file
                    category = self.categorizer.categorize(file_path)
                    
                    # Aggiungi al database
                    self.database.add_file(file_path, content_preview, category, size, modified)
                    indexed_files += 1
                    
                    # Aggiorna la UI con i progressi (solo periodicamente per migliorare le prestazioni)
                    if status_callback and indexed_files % 10 == 0:
                        self.progress_queue.put((indexed_files, total_files, file_path))
                except PermissionError:
                    logger.warning(f"Permesso negato: {file_path}")
                except Exception as e:
                    logger.error(f"Errore nell'elaborazione del file {file_path}: {e}")
            
            # Inizializza la coda dei progressi
            if status_callback:
                self.progress_queue.put((0, 0, "Conteggio dei file in corso..."))
            
            # Conta i file in modo incrementale per evitare blocchi
            if recursive:
                # Utilizza un approccio iterativo anziché recursivo per contare i file
                dirs_to_scan = [root_path]
                processed_dirs = 0
                total_dirs = 1  # Inizia con la directory principale
                
                while dirs_to_scan and not self.stop_event.is_set():
                    current_dir = dirs_to_scan.pop(0)
                    processed_dirs += 1
                    
                    try:
                        with os.scandir(current_dir) as entries:
                            for entry in entries:
                                if self.stop_event.is_set():
                                    break
                                    
                                if entry.is_file():
                                    # Se si applica un filtro estensione, verifica subito
                                    if self.extensions_filter:
                                        _, ext = os.path.splitext(entry.name)
                                        if ext.lower() not in self.extensions_filter:
                                            continue
                                    
                                    total_files += 1
                                    files_to_process.append(entry.path)
                                elif entry.is_dir():
                                    dirs_to_scan.append(entry.path)
                                    total_dirs += 1
                            
                            # Aggiorna periodicamente il progresso del conteggio
                            if status_callback and processed_dirs % 5 == 0:
                                self.progress_queue.put((0, 0, 
                                    f"Conteggio in corso... {total_files} file trovati in {processed_dirs}/{total_dirs} cartelle"))
                    except PermissionError:
                        logger.warning(f"Permesso negato per la directory: {current_dir}")
                    except Exception as e:
                        logger.error(f"Errore nella scansione della directory {current_dir}: {e}")
            else:
                # Solo directory principale, non recursivo
                try:
                    with os.scandir(root_path) as entries:
                        for entry in entries:
                            if entry.is_file():
                                # Se si applica un filtro estensione, verifica subito
                                if self.extensions_filter:
                                    _, ext = os.path.splitext(entry.name)
                                    if ext.lower() not in self.extensions_filter:
                                        continue
                                
                                total_files += 1
                                files_to_process.append(entry.path)
                except Exception as e:
                    logger.error(f"Errore nella scansione della directory {root_path}: {e}")
            
            # Aggiorna lo stato con il conteggio finale
            if status_callback:
                self.progress_queue.put((0, total_files, f"Trovati {total_files} file da processare"))
            
            # Se non ci sono file da processare, termina
            if total_files == 0:
                if status_callback:
                    self.progress_queue.put((0, 0, "Nessun file trovato da processare"))
                return 0
            
            # Processa i file a batch per evitare di saturare la memoria
            with ThreadPoolExecutor(max_workers=min(4, os.cpu_count())) as executor:
                for i in range(0, len(files_to_process), self.max_files_per_batch):
                    if self.stop_event.is_set():
                        break
                        
                    batch = files_to_process[i:i + self.max_files_per_batch]
                    futures = [executor.submit(process_file, file_path) for file_path in batch]
                    
                    # Attendi il completamento del batch
                    for future in futures:
                        future.result()
                    
                    # Aggiorna il database periodicamente per evitare perdite di dati
                    if i % (self.max_files_per_batch * 5) == 0:
                        self.database.save_database()
                        
                    # Aggiorna la UI con i progressi
                    if status_callback:
                        self.progress_queue.put((indexed_files, total_files, 
                                               f"Processati {indexed_files} di {total_files} file"))
            
            # Aggiorna la UI con i progressi finali
            if status_callback:
                self.progress_queue.put((indexed_files, total_files, "Scansione completata"))
            
            # Salva il database al termine della scansione
            self.database.save_database()
            
            return indexed_files
        except Exception as e:
            logger.error(f"Errore nella scansione della directory {root_path}: {e}")
            if status_callback:
                self.progress_queue.put((-1, -1, str(e)))
            return 0
        
    def _get_file_preview(self, file_path, max_size=4096):
        """Ottiene un'anteprima del contenuto del file per l'indicizzazione"""
        try:
            mime_type = mimetypes.guess_type(file_path)[0]
            
            # Tenta di estrarre il testo solo da file appropriati
            if mime_type and (mime_type.startswith('text/') or mime_type in ['application/json', 'application/xml']):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read(max_size)
                except:
                    # In caso di errore nella lettura, utilizza solo il nome del file
                    return os.path.basename(file_path)
            else:
                # Per file binari, usa solo il nome del file
                return os.path.basename(file_path)
        except Exception as e:
            logger.error(f"Errore nella lettura del file {file_path}: {e}")
            return os.path.basename(file_path)
            
class AIFileFinderGUI:
    """Interfaccia grafica dell'applicazione"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("AI File Finder")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Inizializza i componenti principali
        self.database = FileDatabase()
        self.categorizer = FileCategorizer()
        self.scanner = FileScanner(self.database, self.categorizer)
        
        # Thread per gli aggiornamenti UI
        self.update_thread = None
        self.stop_update = False
        
        # Configurazione dello stile dell'interfaccia
        self.setup_styles()
        
        # Crea l'interfaccia grafica
        self.create_gui()
        
        # Avvia il thread di aggiornamento UI
        self.start_update_thread()
        
    def setup_styles(self):
        """Configura gli stili dell'interfaccia"""
        style = ttk.Style()
        
        # Configura il tema se disponibile
        try:
            style.theme_use("clam")
        except:
            pass
            
        style.configure("TButton", padding=6, relief="flat", background="#4a7a8c")
        style.configure("TLabel", padding=6)
        style.configure("TFrame", background="#f0f0f0")
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Result.TFrame", relief="solid", borderwidth=1)
        
    def create_gui(self):
        """Crea l'interfaccia grafica"""
        # Frame principale
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Frame superiore per ricerca e opzioni
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Etichetta di ricerca
        search_label = ttk.Label(top_frame, text="Ricerca:")
        search_label.pack(side=tk.LEFT, padx=5)
        
        # Campo di ricerca
        self.search_entry = ttk.Entry(top_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_entry.bind("<Return>", self.handle_search)
        
        # Pulsante di ricerca
        search_button = ttk.Button(top_frame, text="Cerca", command=self.handle_search)
        search_button.pack(side=tk.LEFT, padx=5)
        
        # Pulsante per selezionare la directory
        scan_button = ttk.Button(top_frame, text="Scansiona Directory", command=self.handle_scan)
        scan_button.pack(side=tk.LEFT, padx=5)
        
        # Frame per le opzioni di ricerca
        options_frame = ttk.LabelFrame(main_frame, text="Opzioni di Ricerca", padding="5")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Opzioni estensioni file
        extensions_frame = ttk.Frame(options_frame)
        extensions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(extensions_frame, text="Estensioni (separare con virgole):").pack(side=tk.LEFT, padx=5)
        self.extensions_entry = ttk.Entry(extensions_frame, width=30)
        self.extensions_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.extensions_entry.insert(0, ".txt,.pdf,.doc,.docx")
        
        # Opzioni categorie
        categories_frame = ttk.Frame(options_frame)
        categories_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(categories_frame, text="Categorie:").pack(side=tk.LEFT, padx=5)
        
        self.categories_var = {}
        categories = ["Documenti", "Immagini", "Video", "Audio", "Codice", "Archivi", "Altri"]
        
        for category in categories:
            var = tk.BooleanVar(value=True)
            self.categories_var[category] = var
            cb = ttk.Checkbutton(categories_frame, text=category, variable=var)
            cb.pack(side=tk.LEFT, padx=5)
        
        # Frame per i risultati di ricerca
        results_frame = ttk.LabelFrame(main_frame, text="Risultati", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Area di visualizzazione dei risultati con scrollbar
        self.results_text = ScrolledText(results_frame, wrap=tk.WORD, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.config(state=tk.DISABLED)
        
        # Frame per la barra di stato e i controlli avanzati
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Barra di progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, side=tk.TOP, padx=5, pady=5)
        
        # Etichetta di stato
        self.status_label = ttk.Label(status_frame, text="Pronto")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Pulsanti avanzati
        advanced_frame = ttk.Frame(status_frame)
        advanced_frame.pack(side=tk.RIGHT, padx=5)
        
        self.stop_button = ttk.Button(advanced_frame, text="Interrompi", command=self.handle_stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.compress_button = ttk.Button(advanced_frame, text="Comprimi Risultati", command=self.handle_compress, state=tk.DISABLED)
        self.compress_button.pack(side=tk.LEFT, padx=5)
        
        self.hash_button = ttk.Button(advanced_frame, text="Calcola Hash", command=self.handle_hash, state=tk.DISABLED)
        self.hash_button.pack(side=tk.LEFT, padx=5)
    
    def start_update_thread(self):
        """Avvia un thread per aggiornare l'interfaccia utente"""
        self.stop_update = False
        
        def update_ui():
            while not self.stop_update:
                try:
                    # Controlla se ci sono messaggi di avanzamento dalla scansione
                    if not self.scanner.progress_queue.empty():
                        current, total, message = self.scanner.progress_queue.get(False)
                        
                        if current >= 0 and total > 0:
                            # Aggiorna la barra di avanzamento
                            progress_percent = min(100, int(current / total * 100))
                            self.progress_var.set(progress_percent)
                            
                            # Aggiorna l'etichetta di stato
                            status = f"Scansionati {current} di {total} file"
                            self.status_label.config(text=status)
                        elif current == -1:
                            # Gestione errori
                            self.status_label.config(text=f"Errore: {message}")
                            messagebox.showerror("Errore di scansione", message)
                        else:
                            # Messaggio finale o stato generale
                            self.status_label.config(text=message)
                            
                            if message == "Scansione completata":
                                messagebox.showinfo("Scansione Completata", 
                                                   f"Scansionati {current} file. Database aggiornato.")
                                self.stop_button.config(state=tk.DISABLED)
                except Exception as e:
                    logger.error(f"Errore nell'aggiornamento dell'UI: {e}")
                    
                # Pausa per ridurre l'utilizzo della CPU
                time.sleep(0.1)
        
        self.update_thread = threading.Thread(target=update_ui, daemon=True)
        self.update_thread.start()
    
    def handle_search(self, event=None):
        """Gestisce la ricerca di file"""
        query = self.search_entry.get().strip()
        
        if not query:
            messagebox.showinfo("Ricerca", "Inserisci un termine di ricerca")
            return
        
        # Prepara i filtri di categoria
        categories = [cat for cat, var in self.categories_var.items() if var.get()]
        
        # Prepara i filtri di estensione
        extensions_text = self.extensions_entry.get().strip()
        extensions = [ext.strip() for ext in extensions_text.split(',')] if extensions_text else None
        
        # Aggiorna lo stato
        self.status_label.config(text="Ricerca in corso...")
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        # Effettua la ricerca in un thread separato
        def do_search():
            results = self.database.search(query, categories, extensions)
            
            # Aggiorna i risultati nella UI
            self.root.after(0, lambda: self.display_search_results(results))
            
        threading.Thread(target=do_search, daemon=True).start()
    
    def display_search_results(self, results):
        """Visualizza i risultati della ricerca"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        if not results:
            self.results_text.insert(tk.END, "Nessun risultato trovato.")
            self.status_label.config(text="Ricerca completata: 0 risultati")
            self.compress_button.config(state=tk.DISABLED)
            self.hash_button.config(state=tk.DISABLED)
            self.results_text.config(state=tk.DISABLED)
            return
        
        # Memorizza i risultati correnti per operazioni successive
        self.current_results = [path for path, _ in results]
        
        # Visualizza i risultati
        self.results_text.insert(tk.END, f"Trovati {len(results)} risultati:\n\n")
        
        for i, (path, score) in enumerate(results, 1):
            file_info = self.database.files_index.get(path, {})
            category = file_info.get('category', 'Non categorizzato')
            
            # Formatta le dimensioni del file
            size_bytes = file_info.get('size', 0)
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f} KB"
            else:
                size_str = f"{size_bytes/(1024*1024):.1f} MB"
            
            # Formatta il timestamp di ultima modifica
            last_modified = file_info.get('last_modified', 0)
            mod_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_modified))
            
            # Aggiunge il risultato formattato
            result_text = (f"{i}. {os.path.basename(path)}\n"
                           f"   Percorso: {path}\n"
                           f"   Categoria: {category}\n"
                           f"   Dimensione: {size_str}\n"
                           f"   Ultima modifica: {mod_time}\n"
                           f"   Rilevanza: {score:.2f}\n\n")
            
            self.results_text.insert(tk.END, result_text)
        
        self.status_label.config(text=f"Ricerca completata: {len(results)} risultati")
        self.compress_button.config(state=tk.NORMAL)
        self.hash_button.config(state=tk.NORMAL)
        self.results_text.config(state=tk.DISABLED)
    
    def handle_scan(self):
        """Gestisce la scansione di una directory"""
        directory = filedialog.askdirectory(title="Seleziona una directory da scansionare")
        
        if not directory:
            return
        
        # Chiedi conferma all'utente prima di iniziare la scansione
        confirm = messagebox.askyesno(
            "Conferma Scansione", 
            "Stai per avviare una scansione della directory selezionata.\n\n"
            "Questo processo indicizzerà i file per ricerche future e potrebbe richiedere tempo.\n"
            "Non è una ricerca immediata.\n\n"
            "Vuoi procedere con la scansione?")
        
        if not confirm:
            return
            
        # Prepara il filtro delle estensioni
        extensions_text = self.extensions_entry.get().strip()
        if extensions_text:
            extensions = [ext.strip() for ext in extensions_text.split(',')]
            self.scanner.set_extensions_filter(extensions)
        else:
            self.scanner.set_extensions_filter(None)
        
        # Aggiorna lo stato
        self.status_label.config(text="Inizializzazione scansione...")
        self.progress_var.set(0)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Scansione in corso...\n")
        self.results_text.insert(tk.END, f"Directory: {directory}\n")
        if extensions_text:
            self.results_text.insert(tk.END, f"Estensioni filtrate: {extensions_text}\n")
        self.results_text.insert(tk.END, "\nAttendi il completamento della scansione.\n")
        self.results_text.insert(tk.END, "Questo processo può richiedere tempo a seconda della quantità di file.\n")
        self.results_text.config(state=tk.DISABLED)
        
        # Avvia la scansione in un thread separato
        def do_scan():
            total_indexed = self.scanner.scan_directory(directory, recursive=True, status_callback=True)
            
            # Al termine, reimposta lo stato dei pulsanti
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
            
            # Aggiorna il testo informativo alla fine
            self.root.after(0, lambda: self.results_text.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.results_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.results_text.insert(tk.END, 
                        f"Scansione completata!\n\n"
                        f"Cartella scansionata: {directory}\n"
                        f"File indicizzati: {total_indexed}\n\n"
                        f"Ora puoi effettuare ricerche utilizzando la casella di ricerca in alto.\n"
                        f"Inserisci un termine di ricerca e fai clic su 'Cerca'."))
            self.root.after(0, lambda: self.results_text.config(state=tk.DISABLED))
            
        self.scan_thread = threading.Thread(target=do_scan, daemon=True)
        self.scan_thread.start()
    
    def handle_stop(self):
        """Interrompe la scansione in corso"""
        self.scanner.stop_scan()
        self.status_label.config(text="Interruzione in corso...")
        self.stop_button.config(state=tk.DISABLED)
    
    def handle_compress(self):
        """Comprime i file nei risultati di ricerca"""
        if not hasattr(self, 'current_results') or not self.current_results:
            messagebox.showinfo("Compressione", "Nessun risultato da comprimere")
            return
            
        # Chiedi il percorso del file di output
        output_path = filedialog.asksaveasfilename(
            title="Salva archivio compresso",
            defaultextension=".zip",
            filetypes=[("Archivi ZIP", "*.zip")]
        )
        
        if not output_path:
            return
            
        # Aggiorna lo stato
        self.status_label.config(text="Compressione in corso...")
        
        # Comprimi i file in un thread separato
        def do_compress():
            compressor = FileCompressor()
            result = compressor.compress_files(self.current_results, output_path)
            
            # Aggiorna l'UI al termine
            if result:
                self.root.after(0, lambda: messagebox.showinfo(
                    "Compressione Completata", 
                    f"File compressi salvati in:\n{output_path}"
                ))
                self.root.after(0, lambda: self.status_label.config(text="Compressione completata"))
            else:
                self.root.after(0, lambda: messagebox.showerror(
                    "Errore di Compressione", 
                    "Si è verificato un errore durante la compressione dei file."
                ))
                self.root.after(0, lambda: self.status_label.config(text="Errore di compressione"))
                
        threading.Thread(target=do_compress, daemon=True).start()
    
    def handle_hash(self):
        """Calcola gli hash forensi per i file nei risultati di ricerca"""
        if not hasattr(self, 'current_results') or not self.current_results:
            messagebox.showinfo("Calcolo Hash", "Nessun risultato per cui calcolare gli hash")
            return
            
        # Chiedi il percorso del file di report
        output_path = filedialog.asksaveasfilename(
            title="Salva report hash",
            defaultextension=".txt",
            filetypes=[("File di testo", "*.txt")]
        )
        
        if not output_path:
            return
            
        # Aggiorna lo stato
        self.status_label.config(text="Calcolo hash in corso...")
        self.progress_var.set(0)
        
        # Calcola gli hash in un thread separato
        def do_hash():
            hasher = FileHasher()
            total_files = len(self.current_results)
            
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write("REPORT HASH FORENSE\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"Data: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Totale file: {total_files}\n\n")
                    
                    for i, file_path in enumerate(self.current_results, 1):
                        # Aggiorna il progresso
                        progress = int((i / total_files) * 100)
                        self.root.after(0, lambda p=progress: self.progress_var.set(p))
                        
                        # Calcola gli hash
                        hashes = hasher.calculate_hash(file_path)
                        
                        # Scrivi nel report
                        f.write(f"File: {file_path}\n")
                        for algo, digest in hashes.items():
                            f.write(f"  {algo.upper()}: {digest}\n")
                        f.write("\n")
                
                # Aggiorna l'UI al termine
                self.root.after(0, lambda: messagebox.showinfo(
                    "Calcolo Hash Completato", 
                    f"Report hash salvato in:\n{output_path}"
                ))
                self.root.after(0, lambda: self.status_label.config(text="Calcolo hash completato"))
            except Exception as e:
                logger.error(f"Errore nella generazione del report hash: {e}")
                self.root.after(0, lambda: messagebox.showerror(
                    "Errore", 
                    f"Si è verificato un errore durante il calcolo degli hash: {str(e)}"
                ))
                self.root.after(0, lambda: self.status_label.config(text="Errore nel calcolo hash"))
                
        threading.Thread(target=do_hash, daemon=True).start()
    
    def on_closing(self):
        """Gestisce la chiusura dell'applicazione"""
        self.stop_update = True
        self.scanner.stop_scan()
        self.database.save_database()
        self.root.destroy()


def run_app():
    """Avvia l'applicazione"""
    root = tk.Tk()
    app = AIFileFinderGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    run_app()
