# Configurador de Nó Ubuntu

Este projeto consiste em um script Python que automatiza a configuração de um nó no Ubuntu, incluindo a instalação do OpenSSH, geração de chaves SSH, configuração de conexões SSH locais e remotas, e coleta de informações de rede.

## Índice

- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Recursos](#recursos)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Requisitos

- **Sistema Operacional:** Ubuntu 20.04 ou superior
- **Python:** 3.6 ou superior
- **Dependências de Sistema:**
  - `python3-tk`
  - `openssh-server`
  - `net-tools`
- **Dependências Python:**
  - `paramiko`
  - `psutil`

## Instalação

### 1. Clone o Repositório

```bash
git clone https://github.com/seu-usuario/configurador-no-ubuntu.git
cd configurador-no-ubuntu

sudo apt-get update
sudo apt-get install -y python3-tk openssh-server net-tools

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python setup_node.py

Passos na Interface Gráfica

    Nome do Nó: Insira o nome desejado para o nó. Evite caracteres inválidos como <, >, :, ", /, \, |, ?, *.
    Tipo de Chave SSH: Selecione o tipo de chave SSH a ser gerada (RSA ou ED25519).
    Adicionar Chave a Servidor Remoto: Marque esta opção se desejar adicionar a chave pública a um servidor remoto. Se marcada, serão exibidos campos adicionais para inserir:
        Host Remoto: Endereço IP ou hostname do servidor remoto.
        Usuário Remoto: Nome de usuário para conexão SSH no servidor remoto.
        Senha Remota: Senha para o usuário remoto (opcional se utilizar autenticação por senha).
    Enviar: Clique neste botão para iniciar o processo de configuração.

Resultados

Após a execução bem-sucedida:

    Diretório do Nó: Um diretório com o nome do nó será criado no diretório atual, contendo:
        Chaves SSH: id_rsa e id_rsa.pub (ou id_ed25519 e id_ed25519.pub).
        Arquivo JSON de Redes: interfaces-ethernet.json contendo informações detalhadas das interfaces de rede e do gateway padrão.
    Arquivo de Log: setup_node.log com logs detalhados das operações realizadas.

Recursos

    Instalação Automatizada do OpenSSH Server
    Geração de Chaves SSH (RSA e ED25519)
    Configuração de Autenticação SSH Local e Remota
    Coleta de Informações de Rede (IPv4 e IPv6)
    Criação de Arquivo JSON com Dados de Rede
    Interface Gráfica Intuitiva com Tkinter
    Sistema de Logging para Depuração e Monitoramento

Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias, correções de bugs ou novos recursos.
Licença

## 3. Criação da ISO Executável do Ubuntu

Para criar uma ISO executável do Ubuntu que inclua e execute automaticamente o script `setup_node.py`, você precisará personalizar uma imagem do Ubuntu Live CD. Este processo envolve várias etapas, incluindo a modificação do ambiente de inicialização, inclusão de pacotes e scripts personalizados, e a criação da imagem ISO final.

### 3.1. Ferramentas Necessárias

- **Cubic (Custom Ubuntu ISO Creator):** Uma ferramenta gráfica para personalizar imagens do Ubuntu.
- **Sistema Operacional:** Uma máquina com Ubuntu instalado.

### 3.2. Passo a Passo para Criar a ISO Personalizada

#### 3.2.1. Instalação do Cubic

```bash
sudo apt-add-repository ppa:cubic-wizard/release
sudo apt update
sudo apt install cubic

Este projeto está licenciado sob a MIT License.