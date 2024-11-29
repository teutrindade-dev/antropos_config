import os
import subprocess
import json
import tkinter as tk
from tkinter import messagebox, filedialog
import paramiko
import psutil
import socket
import logging
from datetime import datetime

# Configuração do logging
logging.basicConfig(
    filename='setup_node.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def install_openssh():
    try:
        logging.info("Atualizando repositórios...")
        subprocess.check_call(['sudo', 'apt-get', 'update'], stdout=subprocess.DEVNULL)
        logging.info("Instalando OpenSSH Server...")
        subprocess.check_call(['sudo', 'apt-get', 'install', '-y', 'openssh-server'], stdout=subprocess.DEVNULL)
        logging.info("OpenSSH instalado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao instalar OpenSSH: {e}")
        messagebox.showerror("Erro", "Falha ao instalar OpenSSH. Verifique as permissões e tente novamente.")
        exit(1)

def create_ssh_keys(save_path, key_type='RSA'):
    try:
        logging.info("Gerando chaves SSH...")
        if key_type.upper() == 'RSA':
            key = paramiko.RSAKey.generate(2048)
        elif key_type.upper() == 'ED25519':
            key = paramiko.Ed25519Key.generate()
        else:
            logging.warning(f"Tipo de chave '{key_type}' não suportado. Usando RSA por padrão.")
            key = paramiko.RSAKey.generate(2048)
        
        private_key_path = os.path.join(save_path, 'id_' + key_type.lower())
        public_key_path = private_key_path + '.pub'

        key.write_private_key_file(private_key_path)
        with open(public_key_path, 'w') as pub_file:
            pub_file.write(f"{key.get_name()} {key.get_base64()}\n")

        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)

        logging.info("Chaves SSH criadas com sucesso.")
        return private_key_path, public_key_path
    except Exception as e:
        logging.error(f"Erro ao criar chaves SSH: {e}")
        messagebox.showerror("Erro", "Falha ao criar chaves SSH.")
        exit(1)

def append_public_key_to_authorized_keys(public_key_path, remote_host=None, remote_username=None, remote_password=None):
    try:
        logging.info("Adicionando chave pública ao authorized_keys...")
        with open(public_key_path, 'r') as pub_file:
            public_key = pub_file.read()

        ssh_dir = os.path.expanduser('~/.ssh')
        authorized_keys_path = os.path.join(ssh_dir, 'authorized_keys')

        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir, mode=0o700)
            logging.info("Diretório ~/.ssh criado com permissões 700.")

        # Evita duplicatas
        with open(authorized_keys_path, 'a+') as auth_file:
            auth_file.seek(0)
            existing_keys = auth_file.read()
            if public_key.strip() not in existing_keys:
                auth_file.write(public_key)
                logging.info("Chave pública adicionada ao authorized_keys.")
            else:
                logging.info("Chave pública já existe no authorized_keys.")

        os.chmod(authorized_keys_path, 0o600)

        # Se for uma conexão remota, adicionar a chave pública também
        if remote_host and remote_username:
            add_key_remote(remote_host, remote_username, public_key, remote_password)
    except Exception as e:
        logging.error(f"Erro ao adicionar chave pública ao authorized_keys: {e}")
        messagebox.showerror("Erro", "Falha ao adicionar chave pública ao authorized_keys.")
        exit(1)

def add_key_remote(host, username, public_key, password=None):
    try:
        logging.info(f"Adicionando chave pública ao servidor remoto {host}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, timeout=10)
        stdin, stdout, stderr = ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')
        stdout.channel.recv_exit_status()

        # Evita duplicatas no remoto
        cmd_check = f'grep "{public_key.strip()}" ~/.ssh/authorized_keys || echo "{public_key.strip()}" >> ~/.ssh/authorized_keys'
        stdin, stdout, stderr = ssh.exec_command(cmd_check)
        stdout.channel.recv_exit_status()

        ssh.exec_command('chmod 600 ~/.ssh/authorized_keys')
        ssh.close()
        logging.info(f"Chave pública adicionada ao servidor remoto {host}.")
    except Exception as e:
        logging.error(f"Erro ao adicionar chave pública no servidor remoto {host}: {e}")
        messagebox.showerror("Erro", f"Falha ao adicionar chave pública no servidor remoto {host}.")
        exit(1)

def restart_ssh_service():
    try:
        logging.info("Reiniciando o serviço SSH...")
        subprocess.check_call(['sudo', 'systemctl', 'restart', 'ssh'], stdout=subprocess.DEVNULL)
        logging.info("Serviço SSH reiniciado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao reiniciar o serviço SSH: {e}")
        messagebox.showerror("Erro", "Falha ao reiniciar o serviço SSH.")
        exit(1)

def test_ssh_connection(private_key_path, host='localhost'):
    try:
        logging.info("Testando conexão SSH...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Recupera o nome do usuário atual
        username = os.getlogin()

        # Testa a conexão SSH no host especificado usando a chave privada
        ssh.connect(hostname=host, username=username, key_filename=private_key_path, timeout=10)
        ssh.close()
        logging.info("Conexão SSH testada com sucesso.")
        return True
    except Exception as e:
        logging.error(f"Falha na conexão SSH: {e}")
        messagebox.showerror("Erro", f"Falha ao testar a conexão SSH: {e}")
        return False

def get_local_ip():
    try:
        logging.info("Obtendo IP local...")
        # Usa psutil para obter as interfaces de rede
        addrs = psutil.net_if_addrs()
        for interface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    logging.info(f"IP encontrado na interface {interface}: {addr.address}")
                    return addr.address
        logging.warning("Nenhum IP não-loopback encontrado. Usando 127.0.0.1")
        return "127.0.0.1"
    except Exception as e:
        logging.error(f"Erro ao obter IP local: {e}")
        return "127.0.0.1"

def get_network_info():
    try:
        logging.info("Obtendo informações de rede...")
        # Obter todas as interfaces e seus endereços
        interfaces = psutil.net_if_addrs()
        
        # Obter gateway padrão usando 'ip route'
        result = subprocess.check_output(['ip', 'route'], encoding='utf-8')
        default_gateway = None
        for line in result.split('\n'):
            if line.startswith('default'):
                parts = line.split()
                default_gateway = parts[2] if len(parts) >= 3 else None
                logging.info(f"Gateway padrão encontrado: {default_gateway}")
                break
        if not default_gateway:
            logging.warning("Nenhum gateway padrão encontrado.")
        
        network_info = {}
        for iface_name, addrs in interfaces.items():
            iface_info = {}
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    iface_info['mac'] = addr.address
                elif addr.family == socket.AF_INET:
                    iface_info['ip'] = addr.address
                    iface_info['netmask'] = addr.netmask
                    iface_info['broadcast'] = addr.broadcast
                elif addr.family == socket.AF_INET6:
                    iface_info['ipv6'] = addr.address
            network_info[iface_name] = iface_info
            logging.info(f"Informações da interface {iface_name}: {iface_info}")

        return network_info, default_gateway
    except Exception as e:
        logging.error(f"Erro ao obter informações de rede: {e}")
        messagebox.showerror("Erro", "Falha ao obter informações de rede.")
        return {}, None

def save_network_info(network_info, gateway, save_path):
    data = {
        "interfaces": network_info,
        "gateway": gateway
    }
    json_path = os.path.join(save_path, 'interfaces-ethernet.json')
    try:
        logging.info(f"Salvando informações de rede em {json_path}...")
        with open(json_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        logging.info(f"Informações de rede salvas em {json_path}.")
    except Exception as e:
        logging.error(f"Erro ao salvar informações de rede: {e}")
        messagebox.showerror("Erro", "Falha ao salvar informações de rede.")

def restart_ssh_service():
    try:
        logging.info("Reiniciando o serviço SSH...")
        subprocess.check_call(['sudo', 'systemctl', 'restart', 'ssh'], stdout=subprocess.DEVNULL)
        logging.info("Serviço SSH reiniciado com sucesso.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Erro ao reiniciar o serviço SSH: {e}")
        messagebox.showerror("Erro", "Falha ao reiniciar o serviço SSH.")
        exit(1)

def main():
    def on_submit():
        node_name = entry.get().strip()
        if not node_name:
            messagebox.showwarning("Aviso", "Por favor, insira o nome do nó.")
            return

        # Validação do nome do nó
        invalid_chars = set(r'<>:"/\|?*')
        if any(c in node_name for c in invalid_chars):
            messagebox.showwarning("Aviso", "O nome do nó contém caracteres inválidos.")
            return

        # Opção para escolher o tipo de chave SSH
        key_type = key_type_var.get()

        # Opção para adicionar chave a um servidor remoto
        add_remote = remote_var.get()
        if add_remote:
            remote_host = remote_host_entry.get().strip()
            remote_username = remote_user_entry.get().strip()
            remote_password = remote_pass_entry.get().strip()
            if not remote_host or not remote_username:
                messagebox.showwarning("Aviso", "Por favor, insira o host e o usuário remoto.")
                return
        else:
            remote_host = None
            remote_username = None
            remote_password = None

        # 2) Cria path no dir com nome <NODE_NAME INPUT>
        base_dir = os.getcwd()
        node_path = os.path.join(base_dir, node_name)
        try:
            os.makedirs(node_path, exist_ok=True)
            logging.info(f"Diretório criado/em uso: {node_path}")
        except Exception as e:
            logging.error(f"Falha ao criar o diretório: {e}")
            messagebox.showerror("Erro", f"Falha ao criar o diretório: {e}")
            return

        # 3) Instala open ssh
        install_openssh()

        # 4) Cria open chaves ssh
        private_key, public_key = create_ssh_keys(node_path, key_type)

        # 4.1) Adiciona a chave pública ao authorized_keys
        append_public_key_to_authorized_keys(public_key, remote_host, remote_username, remote_password)

        # Reinicia o serviço SSH para reconhecer a nova chave
        restart_ssh_service()

        # 5) Testa se chave ssh está ativa e funcional para conexão remota
        if test_ssh_connection(private_key):
            # 6) Salva as chaves ssh na path criada (já foram salvas na função create_ssh_keys)
            pass
        else:
            messagebox.showerror("Erro", "A conexão SSH não está funcional.")
            return

        # 7) Procura o IP e as interfaces de rede
        network_info, gateway = get_network_info()

        # 8) cria arquivo json de nome interfaces-ethernet.json
        save_network_info(network_info, gateway, node_path)

        messagebox.showinfo("Sucesso", f"Configuração do nó '{node_name}' concluída com sucesso.")
        root.destroy()

    # 1) Abrir interface tkinter com nome do nó <NODE_NAME INPUT>
    root = tk.Tk()
    root.title("Configuração de Nó")

    # Layout da interface
    tk.Label(root, text="Nome do Nó:").grid(row=0, column=0, padx=10, pady=10, sticky='e')
    entry = tk.Entry(root, width=30)
    entry.grid(row=0, column=1, padx=10, pady=10)

    # Seleção do tipo de chave SSH
    tk.Label(root, text="Tipo de Chave SSH:").grid(row=1, column=0, padx=10, pady=10, sticky='e')
    key_type_var = tk.StringVar(value='RSA')
    tk.OptionMenu(root, key_type_var, 'RSA', 'ED25519').grid(row=1, column=1, padx=10, pady=10, sticky='w')

    # Opção para adicionar chave a servidor remoto
    remote_var = tk.BooleanVar()
    tk.Checkbutton(root, text="Adicionar chave a servidor remoto", variable=remote_var, command=lambda: toggle_remote_fields()).grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    # Campos para informações do servidor remoto
    remote_host_entry = tk.Entry(root, width=30)
    remote_user_entry = tk.Entry(root, width=30)
    remote_pass_entry = tk.Entry(root, show='*', width=30)

    def toggle_remote_fields():
        if remote_var.get():
            tk.Label(root, text="Host Remoto:").grid(row=3, column=0, padx=10, pady=5, sticky='e')
            remote_host_entry.grid(row=3, column=1, padx=10, pady=5)
            tk.Label(root, text="Usuário Remoto:").grid(row=4, column=0, padx=10, pady=5, sticky='e')
            remote_user_entry.grid(row=4, column=1, padx=10, pady=5)
            tk.Label(root, text="Senha Remota:").grid(row=5, column=0, padx=10, pady=5, sticky='e')
            remote_pass_entry.grid(row=5, column=1, padx=10, pady=5)
        else:
            remote_host_entry.grid_remove()
            remote_user_entry.grid_remove()
            remote_pass_entry.grid_remove()
            for widget in root.grid_slaves():
                if int(widget.grid_info()["row"]) in [3,4,5]:
                    widget.grid_remove()

    # Botão de submissão
    submit_btn = tk.Button(root, text="Enviar", command=on_submit, width=20)
    submit_btn.grid(row=6, column=0, columnspan=2, pady=20)

    root.mainloop()

if __name__ == "__main__":
    main()
