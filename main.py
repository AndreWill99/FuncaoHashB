import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

def hashArquivo(texto):
    sha256 = hashlib.sha256()
    sha256.update(texto.encode('utf-8'))
    return sha256.hexdigest()

def integridade(arquivo, hashInicial):
    try:
        with open(arquivo, 'r', encoding='utf-8') as f:
            conteudo = f.read()
            hashAtual = hashArquivo(conteudo)
            return hashAtual == hashInicial
    except FileNotFoundError:
        messagebox.showerror("Erro", "Arquivo não encontrado.")
        return False

def selecionaArquivo(entrada):
    caminhoArquivo = filedialog.askopenfilename()
    if caminhoArquivo:
        entrada.delete(0, tk.END)
        entrada.insert(0, caminhoArquivo)

def criarHash():
    caminho = inputArquivo.get()
    if caminho:
        try:
            with open(caminho, 'r', encoding='utf-8') as f:
                conteudo = f.read()
                hashGerado = hashArquivo(conteudo)
                entrada.delete(0, tk.END)
                entrada.insert(0, hashGerado)
                messagebox.showinfo("Sucesso", "Hash gerado com sucesso!")
        except FileNotFoundError:
            messagebox.showerror("Erro", "Arquivo não encontrado.")
    else:
        messagebox.showwarning("Atenção", "Selecione um arquivo.")

def verificaArquivo():
    caminho = inputVerificacao.get()
    hashInicial = entrada.get()
    
    if caminho and hashInicial:
        if integridade(caminho, hashInicial):
            messagebox.showinfo("integridade", "O documento está íntegro e não foi alterado.")
        else:
            messagebox.showwarning("integridade", "O documento foi alterado.")
    else:
        messagebox.showwarning("Atenção", "Selecione o arquivo e insira o hash original.")
def comparar_hashes(hash_file_path, file_to_check_path):
    """Compares the hash in a file with the hash of another file."""

    try:
        with open(hash_file_path, 'r') as hash_file:
            stored_hash = hash_file.read().strip()  # Remove whitespace
    except FileNotFoundError:
        messagebox.showerror("Erro", "Arquivo de hash não encontrado.")
        return False  # Indicate failure

    try:
        with open(file_to_check_path, 'r', encoding='utf-8') as file_to_check:
            content = file_to_check.read()
            calculated_hash = hashArquivo(content)
    except FileNotFoundError:
        messagebox.showerror("Erro", "Arquivo para verificação não encontrado.")
        return False

    return stored_hash == calculated_hash



def verificar_hash_de_arquivo(): # New function for the button
    hash_file_path = filedialog.askopenfilename(
        title="Selecione o arquivo de hash", filetypes=[("SHA256 Files", "*.sha256"), ("All Files", "*.*")]
    )
    if not hash_file_path:
        return  # User cancelled

    file_to_check_path = filedialog.askopenfilename(
        title="Selecione o arquivo para comparar", filetypes=[("All Files", "*.*")])

    if not file_to_check_path:
        return  # User cancelled


    if comparar_hashes(hash_file_path, file_to_check_path):
        messagebox.showinfo("Comparação de Hash", "Os hashes correspondem!")
    else:
        messagebox.showerror("Comparação de Hash", "Os hashes NÃO correspondem!")


# Começo da interface


janela = tk.Tk()
janela.title("Verificação de integridade de Documentos")
janela.geometry("500x300")

# Área para inserir o arquivo
tk.Label(janela, text="Arquivo para 'assinar':").pack(pady=5)
frameArquivo = tk.Frame(janela)
frameArquivo.pack(pady=5)
inputArquivo = tk.Entry(frameArquivo, width=40)
inputArquivo.pack(side=tk.LEFT)
btnAbrir = tk.Button(frameArquivo, text="Abrir", command=lambda: selecionaArquivo(inputArquivo))
btnAbrir.pack(side=tk.LEFT, padx=5)


btnVerificarHashArquivo = tk.Button(janela, text="Verificar Hash de Arquivo", command=verificar_hash_de_arquivo)
btnVerificarHashArquivo.pack(pady=10)

# Área de criar o Hash 
btnCriarHash = tk.Button(janela, text="Gerar Hash", command=criarHash)
btnCriarHash.pack(pady=10)

entrada = tk.Entry(janela, width=50)
entrada.pack(pady=5)

# Área de verificar a integridade do hash
tk.Label(janela, text="Arquivo para verificação:").pack(pady=5)
frameVerificacao = tk.Frame(janela)
frameVerificacao.pack(pady=5)
inputVerificacao = tk.Entry(frameVerificacao, width=40)
inputVerificacao.pack(side=tk.LEFT)
btnVerificacao = tk.Button(frameVerificacao, text="Abrir", command=lambda: selecionaArquivo(inputVerificacao))
btnVerificacao.pack(side=tk.LEFT, padx=5)

btnVerificar = tk.Button(janela, text="Verificar integridade", command=verificaArquivo)
btnVerificar.pack(pady=10)

# Fim da interface
janela.mainloop()