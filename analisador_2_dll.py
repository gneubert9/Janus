import tkinter as tk
from tkinter import filedialog, messagebox
import pefile
import os

def analisar_dll(filepath):
    try:
        pe = pefile.PE(filepath)

        info = []
        info.append("=" * 60)
        info.append(f"📁 Nome do Arquivo: {os.path.basename(filepath)}")
        info.append(f"📦 Tamanho: {os.path.getsize(filepath):,} bytes")
        info.append(f"🔢 Arquitetura: {'64-bit' if pe.OPTIONAL_HEADER.Magic == 0x20b else '32-bit'}")
        info.append(f"📌 Entrypoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        info.append(f"🧠 Imagem Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        info.append("=" * 60)
        info.append("\n📥 Importações:\n")

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            info.append(f"  ➜ {entry.dll.decode('utf-8')}:")
            for imp in entry.imports:
                nome = imp.name.decode('utf-8') if imp.name else '---'
                info.append(f"     {hex(imp.address)}\t{nome}")

        return "\n".join(info)
    except Exception as e:
        return f"❌ Erro ao analisar a DLL: {str(e)}"

def drop_file(event):
    filepath = event.data.strip('{}')
    if not filepath.lower().endswith(".dll"):
        messagebox.showerror("Erro", "Por favor, selecione um arquivo .dll")
        return
    resultado = analisar_dll(filepath)
    text_output.delete(1.0, tk.END)
    text_output.insert(tk.END, resultado)

def criar_janela():
    global text_output

    try:
        import tkinterdnd2 as tkdnd
        janela = tkdnd.TkinterDnD.Tk()
        janela.title("Analisador de DLL")
        janela.geometry("800x600")

        instrucoes = tk.Label(janela, text="Arraste um arquivo .dll aqui para analisar", font=("Arial", 14))
        instrucoes.pack(pady=10)

        text_output = tk.Text(janela, wrap=tk.WORD, font=("Courier", 10))
        text_output.pack(expand=True, fill="both", padx=10, pady=10)

        text_output.drop_target_register(tkdnd.DND_FILES)
        text_output.dnd_bind('<<Drop>>', drop_file)

    except ImportError:
        janela = tk.Tk()
        janela.title("Analisador de DLL")
        janela.geometry("800x600")

        instrucoes = tk.Label(janela, text="(Drag-and-drop não disponível)\nClique em 'Abrir DLL' para selecionar um arquivo", font=("Arial", 14))
        instrucoes.pack(pady=10)

        text_output = tk.Text(janela, wrap=tk.WORD, font=("Courier", 10))
        text_output.pack(expand=True, fill="both", padx=10, pady=10)

        def abrir_arquivo():
            filepath = filedialog.askopenfilename(filetypes=[("DLL Files", "*.dll")])
            if filepath:
                resultado = analisar_dll(filepath)
                text_output.delete(1.0, tk.END)
                text_output.insert(tk.END, resultado)

        def salvar_relatorio():
            conteudo = text_output.get(1.0, tk.END)
            if not conteudo.strip():
                messagebox.showwarning("Aviso", "Nada para salvar!")
                return
            arquivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Texto", "*.txt")])
            if arquivo:
                with open(arquivo, "w", encoding="utf-8") as f:
                    f.write(conteudo)
                messagebox.showinfo("Sucesso", "Relatório salvo com sucesso.")

        # ✅ Container para botões centralizados
        botoes_frame = tk.Frame(janela)
        botoes_frame.pack(pady=10)

        botao_abrir = tk.Button(botoes_frame, text="📂 Abrir DLL", width=15, command=abrir_arquivo)
        botao_abrir.grid(row=0, column=0, padx=10)

        botao_salvar = tk.Button(botoes_frame, text="💾 Salvar Relatório", width=15, command=salvar_relatorio)
        botao_salvar.grid(row=0, column=1, padx=10)

    janela.mainloop()

if __name__ == "__main__":
    criar_janela()
