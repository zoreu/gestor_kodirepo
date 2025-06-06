import sys
import os
import io

try:
    import requests
    import ttkbootstrap
except ImportError:
    print("Erro: As bibliotecas 'requests' e 'ttkbootstrap' não estão instaladas.")
    print("Por favor, execute o seguinte comando para instalá-las:")
    print("pip install requests ttkbootstrap")
    sys.exit(1)

import tkinter as tk
from tkinter import filedialog, messagebox, TOP, END, X, LEFT, RIGHT
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import sqlite3
import hashlib
import base64
import xml.etree.ElementTree as ET
import zipfile
import re
from datetime import datetime

class KodiAddonManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Kodi Addon Manager")
        self.style = ttk.Style(theme="darkly")
        self.user = None
        self.setup_db()
        self.config = self.load_config()
        self.setup_login()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_db(self):
        """Inicializa o banco SQLite para configurações e usuários."""
        self.conn = sqlite3.connect("config.db")
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def load_config(self):
        """Carrega configurações do SQLite."""
        config = {"github_token": "", "github_owner": "", "github_repo": ""}
        cursor = self.conn.cursor()
        cursor.execute("SELECT key, value FROM config")
        for key, value in cursor.fetchall():
            config[key] = value
        return config

    def close_db(self):
        """Fecha a conexão com o banco SQLite."""
        if hasattr(self, 'conn'):
            self.conn.close()

    def on_closing(self):
        """Fecha o banco e encerra a aplicação."""
        self.close_db()
        self.root.destroy()

    def search_addons(self, addon_id, kodi_version, parent_frame):
        """Pesquisa addons no repositório e exibe com texto 'Remover' clicável e linhas separadoras."""
        if not addon_id or not kodi_version or kodi_version not in ["leia", "matrix", "nexus"]:
            messagebox.showerror("Erro", "ID do addon e versão do Kodi são obrigatórios.")
            return

        # Limpar resultados anteriores
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Listar addons
        endpoint = f"contents/{kodi_version}"
        response = self.github_api_request(endpoint)
        if response["code"] != 200:
            messagebox.showerror("Erro", f"Erro na API: {response['data'].get('message', 'Desconhecido')}")
            return

        addons = []
        for item in response["data"]:
            if item["type"] == "dir" and (not addon_id or addon_id in item["name"]):
                sub_endpoint = f"contents/{kodi_version}/{item['name']}"
                sub_response = self.github_api_request(sub_endpoint)
                if sub_response["code"] != 200:
                    continue
                for file in sub_response["data"]:
                    match = re.match(rf"^{item['name']}[-_]?(.+)?\.zip$", file["name"])
                    if match:
                        version = match.group(1) or "unknown"
                        addons.append({
                            "id": item["name"],
                            "version": version,
                            "path": f"{kodi_version}/{item['name']}/{file['name']}",
                            "sha": file["sha"],
                            "kodi_version": kodi_version
                        })

        if not addons:
            ttk.Label(self.results_frame, text="Nenhum addon encontrado.", font=("Arial", 12)).pack()
            return

        # Configurar estilo do Treeview com linhas separadoras
        style = ttk.Style()
        style.configure("Custom.Treeview", rowheight=30, font=("Arial", 10))
        style.configure("Custom.Treeview.Heading", font=("Arial", 12, "bold"))
        style.configure("Custom.Treeview", borderwidth=1, relief="solid")
        style.map("Custom.Treeview", background=[('selected', '#495057'), ('!selected', '#212529')])

        # Criar Treeview
        tree = ttk.Treeview(
            self.results_frame,
            columns=("ID", "Version", "Action"),
            show="headings",
            style="Custom.Treeview",
            height=len(addons)
        )
        tree.heading("ID", text="ID")
        tree.heading("Version", text="Versão")
        tree.heading("Action", text="Ação")
        tree.column("ID", width=300, anchor="w")
        tree.column("Version", width=150, anchor="center")
        tree.column("Action", width=100, anchor="center")
        tree.pack(expand=True, fill="both", padx=5, pady=5)

        # Configurar tag para texto "Remover" (estilo de link clicável)
        tree.tag_configure("remove_link", foreground="#ff4d4d", font=("Arial", 10, "underline"))

        # Adicionar addons à tabela
        for addon in addons:
            tree.insert(
                "",
                END,
                values=(addon["id"], addon["version"], "Remover"),
                tags=("remove_link",),
                iid=addon["path"]
            )

        # Binding para cliques na coluna "Ação"
        def on_tree_click(event):
            region = tree.identify_region(event.x, event.y)
            if region != "cell":
                return
            column = tree.identify_column(event.x)
            if column != "#3":
                return
            item = tree.identify_row(event.y)
            if not item:
                return
            for addon in addons:
                if addon["path"] == item:
                    self.remove_addon(
                        addon["path"],
                        addon["id"],
                        addon["version"],
                        addon["kodi_version"],
                        addon["sha"],
                        addon_id,  # Pass addon_id for refresh
                        kodi_version,  # Pass kodi_version for refresh
                        parent_frame  # Pass parent_frame for refresh
                    )
                    break

        tree.bind("<Button-1>", on_tree_click)

    def save_config(self, token, owner, repo):
        """Salva configurações no SQLite."""
        cursor = self.conn.cursor()
        cursor.executemany(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            [("github_token", token), ("github_owner", owner), ("github_repo", repo)]
        )
        self.conn.commit()
        self.config = {"github_token": token, "github_owner": owner, "github_repo": repo}

    def github_api_request(self, endpoint, method="GET", data=None):
        """Faz requisições à API do GitHub."""
        url = f"https://api.github.com/repos/{self.config['github_owner']}/{self.config['github_repo']}/{endpoint}"
        headers = {
            "Authorization": f"token {self.config['github_token']}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Python-Kodi-Addon-Manager"
        }
        try:
            if method == "GET":
                response = requests.get(url, headers=headers)
            elif method == "PUT":
                response = requests.put(url, headers=headers, json=data)
            elif method == "DELETE":
                response = requests.delete(url, headers=headers, json=data)
            response.raise_for_status()
            remaining = int(response.headers.get("X-RateLimit-Remaining", 5000))
            if remaining <= 10:
                with open("logs/api_errors.log", "a") as f:
                    f.write(f"[{datetime.now()}] Aviso: Limite de API próximo do fim ({remaining})\n")
            return {"code": response.status_code, "data": response.json() if response.content else {}}
        except requests.RequestException as e:
            with open("logs/api_errors.log", "a") as f:
                f.write(f"[{datetime.now()}] Erro na API: {str(e)}\n")
            return {"code": 500, "data": {"message": str(e)}}

    def setup_login(self):
        """Tela de login."""
        self.clear_window()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        ttk.Label(frame, text="Kodi Addon Manager", font=("Arial", 16, "bold")).pack(pady=10)
        ttk.Label(frame, text="Usuário", font=("Arial", 12)).pack()
        username_entry = ttk.Entry(frame, width=30)
        username_entry.pack(pady=5)
        ttk.Label(frame, text="Senha", font=("Arial", 12)).pack()
        password_entry = ttk.Entry(frame, width=30, show="*")
        password_entry.pack(pady=5)
        ttk.Button(frame, text="Entrar", bootstyle="primary", command=lambda: self.login(username_entry.get(), password_entry.get())).pack(pady=10)
        ttk.Button(frame, text="Cadastrar", bootstyle="secondary", command=self.setup_register).pack(pady=5)

    def login(self, username, password):
        """Autentica o usuário."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user and hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 100000).hex() == user[0]:
            self.user = username
            self.setup_main_interface()
        else:
            messagebox.showerror("Erro", "Usuário ou senha inválidos.")

    def setup_register(self):
        """Tela de cadastro."""
        self.clear_window()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True, fill="both")
        ttk.Label(frame, text="Cadastro", font=("Arial", 16, "bold")).pack(pady=10)
        ttk.Label(frame, text="Usuário", font=("Arial", 12)).pack()
        username_entry = ttk.Entry(frame, width=30)
        username_entry.pack(pady=5)
        ttk.Label(frame, text="Senha", font=("Arial", 12)).pack()
        password_entry = ttk.Entry(frame, width=30, show="*")
        password_entry.pack(pady=5)
        ttk.Button(frame, text="Cadastrar", bootstyle="primary", command=lambda: self.register(username_entry.get(), password_entry.get())).pack(pady=10)
        ttk.Button(frame, text="Voltar", bootstyle="secondary", command=self.setup_login).pack(pady=5)

    def register(self, username, password):
        """Cadastra um novo usuário."""
        if not re.match(r"^[a-zA-Z0-9_-]{3,50}$", username):
            messagebox.showerror("Erro", "Usuário deve ter entre 3 e 50 caracteres alfanuméricos.")
            return
        if len(password) < 8:
            messagebox.showerror("Erro", "Senha deve ter pelo menos 8 caracteres.")
            return
        cursor = self.conn.cursor()
        try:
            hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), b"salt", 100000).hex()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            self.conn.commit()
            messagebox.showinfo("Sucesso", "Usuário cadastrado com sucesso!")
            self.setup_login()
        except sqlite3.IntegrityError:
            messagebox.showerror("Erro", "Usuário já existe.")

    def clear_window(self):
        """Limpa a janela atual."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def setup_main_interface(self):
        """Interface principal com abas."""
        self.clear_window()
        self.root.geometry("800x600")
        navbar = ttk.Frame(self.root)
        navbar.pack(side=TOP, fill=X, padx=10, pady=5)
        ttk.Label(navbar, text=f"Bem-vindo, {self.user}", font=("Arial", 12)).pack(side=LEFT)
        ttk.Button(navbar, text="Sair", bootstyle="danger", command=self.logout).pack(side=RIGHT)
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.setup_config_tab(notebook)
        self.setup_search_tab(notebook)
        self.setup_upload_tab(notebook)

    def logout(self):
        """Encerra a sessão."""
        self.user = None
        self.setup_login()

    def setup_config_tab(self, notebook):
        """Aba de configurações."""
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Configurações")
        ttk.Label(frame, text="Token do GitHub", font=("Arial", 12)).pack()
        token_entry = ttk.Entry(frame, width=50)
        token_entry.insert(0, self.config["github_token"])
        token_entry.pack(pady=5)
        ttk.Label(frame, text="Proprietário do Repositório", font=("Arial", 12)).pack()
        owner_entry = ttk.Entry(frame, width=50)
        owner_entry.insert(0, self.config["github_owner"])
        owner_entry.pack(pady=5)
        ttk.Label(frame, text="Nome do Repositório", font=("Arial", 12)).pack()
        repo_entry = ttk.Entry(frame, width=50)
        repo_entry.insert(0, self.config["github_repo"])
        repo_entry.pack(pady=5)
        ttk.Button(frame, text="Salvar", bootstyle="primary", command=lambda: self.save_config(
            token_entry.get(), owner_entry.get(), repo_entry.get()
        )).pack(pady=10)

    def setup_search_tab(self, notebook):
        """Aba de pesquisa e remoção."""
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Pesquisar e Remover")
        ttk.Label(frame, text="Pesquisar Addon", font=("Arial", 16, "bold")).pack()
        
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=X, pady=10)
        ttk.Label(search_frame, text="ID do Addon", font=("Arial", 12)).pack(side=LEFT)
        addon_id_entry = ttk.Entry(search_frame, width=30)
        addon_id_entry.pack(side=LEFT, padx=5)
        ttk.Label(search_frame, text="Versão do Kodi", font=("Arial", 12)).pack(side=LEFT)
        kodi_version = ttk.Combobox(search_frame, values=["leia", "matrix", "nexus"], width=15)
        kodi_version.pack(side=LEFT, padx=5)
        ttk.Button(search_frame, text="Pesquisar", bootstyle="primary", command=lambda: self.search_addons(
            addon_id_entry.get(), kodi_version.get(), frame
        )).pack(side=LEFT, padx=5)
        
        self.results_frame = ttk.Frame(frame)
        self.results_frame.pack(expand=True, fill="both")

    def remove_addon(self, addon_path, addon_id, addon_version, kodi_version, sha, search_addon_id, search_kodi_version, parent_frame):
        """Remove um addon do repositório."""
        if not messagebox.askyesno("Confirmação", f"Tem certeza que deseja remover {addon_id} v{addon_version}?"):
            return
        
        # Remover o arquivo ZIP
        endpoint = f"contents/{addon_path}"
        data = {"message": f"Remove {addon_id} v{addon_version} de {kodi_version}", "sha": sha}
        response = self.github_api_request(endpoint, method="DELETE", data=data)
        if response["code"] != 200:
            messagebox.showerror("Erro", f"Erro ao remover o ZIP: {response['data'].get('message', 'Desconhecido')}")
            return
        
        # Listar outros ZIPs na pasta do addon
        addon_folder = f"{kodi_version}/{addon_id}"
        response = self.github_api_request(f"contents/{addon_folder}")
        remaining_zips = []
        if response["code"] == 200:
            for file in response["data"]:
                match = re.match(rf"^{addon_id}-([0-9.]+)\.zip$", file["name"])
                if match:
                    remaining_zips.append({
                        "version": match.group(1),
                        "path": file["path"],
                        "sha": file["sha"]
                    })
        
        # Atualizar addon.xml com a maior versão, se houver
        addon_xml = None
        latest_version = None
        if remaining_zips:
            remaining_zips.sort(key=lambda x: x["version"], reverse=True)
            latest_zip = remaining_zips[0]
            latest_version = latest_zip["version"]
            
            # Baixar o ZIP da maior versão
            response = self.github_api_request(f"contents/{latest_zip['path']}?ref=main")
            if response["code"] != 200:
                messagebox.showerror("Erro", f"Erro ao obter o ZIP da maior versão.")
                return
            
            zip_content = base64.b64decode(response["data"]["content"])
            temp_zip = "temp_addon.zip"
            with open(temp_zip, "wb") as f:
                f.write(zip_content)
            
            try:
                with zipfile.ZipFile(temp_zip, "r") as zip_ref:
                    for entry in zip_ref.namelist():
                        if re.match(rf"^{addon_id}/addon\.xml$", entry):
                            addon_xml = zip_ref.read(entry).decode("utf-8")
                            break
                os.remove(temp_zip)
            except Exception as e:
                os.remove(temp_zip)
                messagebox.showerror("Erro", f"Erro ao abrir o ZIP: {str(e)}")
                return
            
            if not addon_xml:
                messagebox.showerror("Erro", "addon.xml não encontrado no ZIP da maior versão.")
                return
            
            # Fazer upload do addon.xml
            endpoint = f"contents/{kodi_version}/{addon_id}/addon.xml"
            response = self.github_api_request(endpoint)
            data = {
                "message": f"Atualiza addon.xml para {addon_id} v{latest_version} em {kodi_version}",
                "content": base64.b64encode(addon_xml.encode()).decode()
            }
            if response["code"] == 200:
                data["sha"] = response["data"]["sha"]
            response = self.github_api_request(endpoint, method="PUT", data=data)
            if response["code"] not in [200, 201]:
                messagebox.showerror("Erro", f"Erro ao atualizar addon.xml: {response['data'].get('message', 'Desconhecido')}")
                return
        else:
            # Remover addon.xml e arquivos de mídia
            files_to_remove = ["addon.xml", "icon.png", "fanart.jpg", "fanart.png"]
            for filename in files_to_remove:
                file_path = f"{kodi_version}/{addon_id}/{filename}"
                response = self.github_api_request(f"contents/{file_path}")
                if response["code"] == 200:
                    data = {"message": f"Remove {filename} de {addon_id} em {kodi_version}", "sha": response["data"]["sha"]}
                    response = self.github_api_request(f"contents/{file_path}", method="DELETE", data=data)
                    if response["code"] != 200:
                        messagebox.showerror("Erro", f"Erro ao remover {filename}: {response['data'].get('message', 'Desconhecido')}")
                        return
        
        # Atualizar addons.xml
        endpoint = f"contents/{kodi_version}/addons.xml"
        response = self.github_api_request(endpoint)
        dom = ET.ElementTree(ET.Element("addons"))
        sha = None
        if response["code"] == 200:
            xml_content = base64.b64decode(response["data"]["content"]).decode("utf-8")
            xml_content = self.corrigir_addons_xml(xml_content)
            if not xml_content:
                messagebox.showerror("Erro", "Erro: addons.xml corrompido e não recuperável.")
                return
            dom.parse(io.StringIO(xml_content))
            sha = response["data"]["sha"]
        
        addons = dom.getroot()
        for addon in list(addons.findall("addon")):
            if addon.get("id") == addon_id and addon.get("version") == addon_version:
                addons.remove(addon)
        
        if remaining_zips and addon_xml:
            entry_exists = any(addon.get("id") == addon_id and addon.get("version") == latest_version for addon in addons.findall("addon"))
            if not entry_exists:
                addon_tree = ET.ElementTree()
                addon_tree.parse(io.StringIO(addon_xml))
                addons.append(addon_tree.getroot())
        
        if not addons.findall("addon"):
            addons.append(ET.Comment(" No addons currently in this repository "))
        
        new_addons_xml = ET.tostring(addons, encoding="unicode", xml_declaration=True)
        data = {
            "message": f"Atualiza addons.xml após remoção de {addon_id} v{addon_version} em {kodi_version}",
            "content": base64.b64encode(new_addons_xml.encode()).decode()
        }
        if sha:
            data["sha"] = sha
        response = self.github_api_request(endpoint, method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao atualizar addons.xml: {response['data'].get('message', 'Desconhecido')}")
            return
        
        # Atualizar addons.xml.md5
        md5_hash = hashlib.md5(new_addons_xml.encode()).hexdigest()
        endpoint = f"contents/{kodi_version}/addons.xml.md5"
        response = self.github_api_request(endpoint)
        data = {
            "message": f"Atualiza addons.xml.md5 após remoção de {addon_id} v{addon_version} em {kodi_version}",
            "content": base64.b64encode(md5_hash.encode()).decode()
        }
        if response["code"] == 200:
            data["sha"] = response["data"]["sha"]
        response = self.github_api_request(endpoint, method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao atualizar addons.xml.md5: {response['data'].get('message', 'Desconhecido')}")
            return

        messagebox.showinfo("Sucesso", f"Addon {addon_id} v{addon_version} removido com sucesso de {kodi_version}!")
        self.search_addons(search_addon_id, search_kodi_version, parent_frame)

    def corrigir_addons_xml(self, xml_content):
        """Corrige o XML do addons.xml."""
        xml_content = re.sub(r"^\ufeff", "", xml_content).strip()
        if not xml_content:
            return '<?xml version="1.0" encoding="UTF-8"?><addons></addons>'
        
        tree = ET.ElementTree()
        try:
            tree.parse(io.StringIO(xml_content))
        except ET.ParseError:
            with open("logs/addons_xml.log", "a") as f:
                f.write(f"[{datetime.now()}] Erro ao parsear XML inicial: {xml_content[:100]}\n")
            matches = re.findall(r"<addon\b[^>]*>.*?</addon>", xml_content, re.DOTALL)
            tree = ET.ElementTree(ET.Element("addons"))
            for addon_xml in matches:
                try:
                    addon_tree = ET.ElementTree()
                    addon_tree.parse(io.StringIO(addon_xml))
                    tree.getroot().append(addon_tree.getroot())
                except ET.ParseError:
                    continue
            if not tree.getroot().findall("addon"):
                return None
        
        seen_ids = {}
        for addon in list(tree.getroot().findall("addon")):
            id_ = addon.get("id")
            if id_ in seen_ids:
                existing = seen_ids[id_]
                if version_compare(addon.get("version"), existing.get("version")) > 0:
                    tree.getroot().remove(existing)
                    seen_ids[id_] = addon
                else:
                    tree.getroot().remove(addon)
            else:
                seen_ids[id_] = addon
        return ET.tostring(tree.getroot(), encoding="unicode", xml_declaration=True)

    def setup_upload_tab(self, notebook):
        """Aba de upload de addons."""
        frame = ttk.Frame(notebook, padding=20)
        notebook.add(frame, text="Upload de Addon")
        ttk.Label(frame, text="Upload de Addon", font=("Arial", 16, "bold")).pack()
        ttk.Label(frame, text="Arquivo ZIP", font=("Arial", 12)).pack()
        file_entry = ttk.Entry(frame, width=50)
        file_entry.pack(pady=5)
        ttk.Button(frame, text="Selecionar Arquivo", bootstyle="secondary", command=lambda: self.select_file(file_entry)).pack()
        ttk.Label(frame, text="Versão do Kodi", font=("Arial", 12)).pack()
        kodi_version = ttk.Combobox(frame, values=["leia", "matrix", "nexus"], width=15)
        kodi_version.pack(pady=5)
        ttk.Button(frame, text="Enviar Addon", bootstyle="primary", command=lambda: self.upload_addon(
            file_entry.get(), kodi_version.get()
        )).pack(pady=10)

    def select_file(self, entry):
        """Seleciona um arquivo ZIP."""
        file_path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if file_path:
            entry.delete(0, END)
            entry.insert(0, file_path)

    def upload_addon(self, file_path, kodi_version):
        """Faz upload de um addon para o repositório."""
        if not file_path or not kodi_version or kodi_version not in ["leia", "matrix", "nexus"]:
            messagebox.showerror("Erro", "Arquivo ZIP e versão do Kodi são obrigatórios.")
            return
        if not os.path.exists(file_path) or not file_path.lower().endswith(".zip"):
            messagebox.showerror("Erro", "Apenas arquivos ZIP são permitidos.")
            return
        if os.path.getsize(file_path) > 50 * 1024 * 1024:
            messagebox.showerror("Erro", "Arquivo muito grande (máximo 50 MB).")
            return
        
        # Validar o ZIP
        addon_xml = None
        addon_id = None
        addon_path = None
        media_files = {}
        try:
            with zipfile.ZipFile(file_path, "r") as zip_ref:
                for entry in zip_ref.namelist():
                    if re.match(r"[^/]+/addon\.xml$", entry):
                        addon_xml = zip_ref.read(entry).decode("utf-8")
                        addon_path = entry
                        addon_id = entry.split("/")[0]
                    elif re.match(r"[^/]+/(icon\.png|fanart\.(jpg|png))$", entry):
                        parts = entry.split("/")
                        if parts[0] == addon_id or not addon_id:
                            media_files[parts[1]] = zip_ref.read(entry)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir o ZIP: {str(e)}")
            return
        
        if not addon_xml or not addon_id:
            messagebox.showerror("Erro", "addon.xml não encontrado ou estrutura inválida.")
            return
        
        # Parsear addon.xml
        try:
            xml = ET.ElementTree()
            xml.parse(io.StringIO(addon_xml))
            xml_id = xml.getroot().get("id")
            version = xml.getroot().get("version")
            if not xml_id or not version:
                messagebox.showerror("Erro", "addon.xml inválido: ID ou versão não encontrados.")
                return
            if xml_id != addon_id:
                messagebox.showerror("Erro", f"O ID no addon.xml ({xml_id}) não corresponde à pasta ({addon_id}).")
                return
            platform_nodes = xml.findall(".//extension[@point='xbmc.addon.metadata']/platform")
            platform = platform_nodes[0].text if platform_nodes else "all"
            if kodi_version == "leia" and platform not in ["all", "leia", "krypton"]:
                messagebox.showerror("Erro", "Este addon não é compatível com o Kodi Leia.")
                return
            if kodi_version == "nexus" and platform not in ["all", "nexus", "matrix"]:
                messagebox.showerror("Erro", "Este addon não é compatível com o Kodi Nexus.")
                return
        except ET.ParseError:
            messagebox.showerror("Erro", "addon.xml inválido.")
            return
        
        # Verificar se o addon já existe
        path = f"{kodi_version}/{addon_id}/{addon_id}-{version}.zip"
        response = self.github_api_request(f"contents/{path}")
        if response["code"] == 200:
            messagebox.showerror("Erro", f"O addon {addon_id} v{version} já existe no repositório {kodi_version}.")
            return
        
        # Fazer upload do ZIP
        with open(file_path, "rb") as f:
            zip_content = base64.b64encode(f.read()).decode()
        data = {"message": f"Adiciona {addon_id} v{version} para {kodi_version}", "content": zip_content}
        response = self.github_api_request(f"contents/{path}", method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao fazer upload do ZIP: {response['data'].get('message', 'Desconhecido')}")
            return
        
        # Fazer upload do addon.xml
        endpoint = f"contents/{kodi_version}/{addon_id}/addon.xml"
        response = self.github_api_request(endpoint)
        data = {"message": f"Adiciona addon.xml para {addon_id} v{version} em {kodi_version}", "content": base64.b64encode(addon_xml.encode()).decode()}
        if response["code"] == 200:
            data["sha"] = response["data"]["sha"]
        response = self.github_api_request(endpoint, method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao fazer upload do addon.xml: {response['data'].get('message', 'Desconhecido')}")
            return
        
        # Fazer upload dos arquivos de mídia
        for filename, content in media_files.items():
            endpoint = f"contents/{kodi_version}/{addon_id}/{filename}"
            response = self.github_api_request(endpoint)
            data = {"message": f"Adiciona {filename} para {addon_id} v{version} em {kodi_version}", "content": base64.b64encode(content).decode()}
            if response["code"] == 200:
                data["sha"] = response["data"]["sha"]
            response = self.github_api_request(endpoint, method="PUT", data=data)
            if response["code"] not in [200, 201]:
                messagebox.showerror("Erro", f"Erro ao fazer upload de {filename}: {response['data'].get('message', 'Desconhecido')}")
                return
        
        # Atualizar addons.xml
        endpoint = f"contents/{kodi_version}/addons.xml"
        response = self.github_api_request(endpoint)
        dom = ET.ElementTree(ET.Element("addons"))
        sha = None
        if response["code"] == 200:
            xml_content = base64.b64decode(response["data"]["content"]).decode("utf-8")
            xml_content = self.corrigir_addons_xml(xml_content)
            if not xml_content:
                messagebox.showerror("Erro", "Erro: addons.xml corrompido e não recuperável.")
                return
            dom.parse(io.StringIO(xml_content))
            sha = response["data"]["sha"]
        
        addons = dom.getroot()
        addon_node = xml.getroot()
        addons.append(addon_node)
        
        new_addons_xml = ET.tostring(addons, encoding="unicode", xml_declaration=True)
        data = {"message": f"Atualiza addons.xml para {addon_id} v{version} em {kodi_version}", "content": base64.b64encode(new_addons_xml.encode()).decode()}
        if sha:
            data["sha"] = sha
        response = self.github_api_request(endpoint, method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao atualizar addons.xml: {response['data'].get('message', 'Desconhecido')}")
            return
        
        # Atualizar addons.xml.md5
        md5_hash = hashlib.md5(new_addons_xml.encode()).hexdigest()
        endpoint = f"contents/{kodi_version}/addons.xml.md5"
        response = self.github_api_request(endpoint)
        data = {"message": f"Atualiza addons.xml.md5 para {kodi_version}", "content": base64.b64encode(md5_hash.encode()).decode()}
        if response["code"] == 200:
            data["sha"] = response["data"]["sha"]
        response = self.github_api_request(endpoint, method="PUT", data=data)
        if response["code"] not in [200, 201]:
            messagebox.showerror("Erro", f"Erro ao atualizar addons.xml.md5: {response['data'].get('message', 'Desconhecido')}")
            return
        
        messagebox.showinfo("Sucesso", f"Addon {addon_id} v{version} adicionado com sucesso ao repositório {kodi_version}!")

def version_compare(v1, v2):
    """Compara versões de addons."""
    v1_parts = [int(x) for x in v1.split(".")]
    v2_parts = [int(x) for x in v2.split(".")]
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_num = v1_parts[i] if i < len(v1_parts) else 0
        v2_num = v2_parts[i] if i < len(v2_parts) else 0
        if v1_num != v2_num:
            return 1 if v1_num > v2_num else -1
    return 0

if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    root = ttk.Window()
    app = KodiAddonManager(root)
    root.mainloop()