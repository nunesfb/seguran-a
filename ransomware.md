# 🔹 Ransomware

## 📌 Definição
**Ransomware** é um tipo de malware de **extorsão** que **sequestra dados** por criptografia e exige **pagamento de resgate** (geralmente em criptomoedas) para suposta recuperação.

---

## 🔧 Como funciona (alto nível)
- **Acesso inicial:** engenharia social (phishing), exploração de serviços expostos (RDP/SMB), downloads enganosos.
- **Preparação:** reconhecimento do ambiente, tentativa de elevar privilégios e localizar dados/compartilhamentos.
- **Persistência & evasão:** criação de tarefas/serviços, ofuscação, tentativa de desativar defesas.
- **Criptografia:** escolha de diretórios-alvo, geração/derivação de chaves, criptografia em massa, **anotações de resgate**.
- **Extorsão:** simples (criptografia) ou **dupla** (criptografia + ameaça de vazamento de dados).
- **Movimento lateral:** após um host, tenta alcançar **outros** para ampliar o impacto.

---

## 📡 Propagação
- Phishing com links/arquivos maliciosos.  
- Documentos com macros.  
- Exploração de vulnerabilidades (RDP/SMB).  
- Downloads infectados.  
- Movimento lateral na rede.  

---

## 💥 Impactos
- **Indisponibilidade** de dados/sistemas.  
- **Paralisação** de operações.  
- **Perdas financeiras** (recuperação, multas, interrupção).  
- **Danos reputacionais**.  
- **Vazamento** de dados (*double extortion*).  

---

## 🧬 Tipos (alto nível)
1. **Crypto-Ransomware:** criptografa arquivos (ex.: “.lock”, “.encrypted”).  
2. **Locker Ransomware:** bloqueia a **tela**/sessão sem criptografar arquivos.  
3. **Scareware:** simula “infecções” para induzir pagamento.  
4. **Doxware/Leakware:** rouba e ameaça **publicar** dados.  
5. **RaaS (Ransomware-as-a-Service):** afiliados “alugam” a operação.  
6. **Mobile Ransomware:** bloqueia PIN/criptografa dados em **smartphones**.  

---

## 🔎 IoCs (Indicadores de Comprometimento)
- **Pico súbito** de criação/modificação/renomeação de arquivos.  
- **Novas extensões** nos arquivos (ex.: sufixos incomuns) e **notas de resgate** em várias pastas.  
- Processos invocando **criptografia intensiva** e acessos simultâneos a muitos diretórios compartilhados.  
- **Tentativas de desabilitar proteções** e apagar cópias de segurança locais.  
- **Beacons** para domínios recém-registrados; conexões a serviços de anonimato.  
- Criação de **tarefas/serviços** recentes e alterações em políticas de segurança.

---

## 🛡️ Mitigação & Resposta
**Prevenção**
- **Backups 3-2-1** testados e, se possível, **imutáveis/offline**.  
- **MFA** (especialmente para VPN/RDP/SSO) e **privilégios mínimos**.  
- **Patching** e redução de superfície (fechar RDP à internet; usar VPN/proxy).  
- **EDR/XDR** com bloqueio comportamental, isolamento rápido e regras para *ransom notes* / explosões de I/O.  
- **Segmentação de rede**, catálogo de software e **allowlisting**.

**Resposta (alto nível)**
- **Isolar** rapidamente o host/rede afetados.  
- **Preservar artefatos** (logs/memória) e identificar “paciente zero”.  
- **Erradicar persistências**, **rotacionar credenciais**, revisar acessos.  
- **Restaurar** somente de **backups limpos**; validar integridade antes de reintroduzir em produção.  
- **Comunicação** coordenada (jurídico, stakeholders) e lições aprendidas.

---

## 🧪 Demos

> Objetivo: **ilustrar conceitos** (bloqueio, criptografia, resposta e detecção) **sem** tocar em arquivos do sistema ou automatizar comportamentos maliciosos.

### 1) “Locker” didático (bloqueio de tela **falso**)
*Simula um bloqueio com mensagem de “resgate”; um código conhecido ‘desbloqueia’.*  
Salve como `locker_demo.html` e abra no navegador.

```html
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>[DEMO] Locker (simulação inofensiva)</title>
<style>
  body{margin:0;font-family:system-ui;background:#0b0f1a;color:#e7ecf3}
  .full{position:fixed;inset:0;display:grid;place-items:center;background:#0b0f1acc}
  .card{max-width:560px;background:#141a2b;border:1px solid #26324a;border-radius:16px;padding:24px;box-shadow:0 16px 48px rgba(0,0,0,.5)}
  input,button{padding:10px 12px;border-radius:10px;border:1px solid #2f3d5a}
  button{background:#4f7cff;color:#fff;border:0;font-weight:700;cursor:pointer}
  .muted{color:#9fb1d1}
</style>
</head>
<body>
  <div class="full" id="overlay">
    <div class="card" role="alertdialog" aria-label="Simulação de ransom locker">
      <h1>🔒 Seus dados foram “bloqueados” (DEMO)</h1>
      <p class="muted">Isto é uma simulação educativa. Nada foi criptografado.</p>
      <p>Para desbloquear, insira o <strong>código didático</strong> e clique em “Desbloquear”.</p>
      <div style="display:flex;gap:8px">
        <input id="code" placeholder="Código">
        <button id="unlock">Desbloquear</button>
      </div>
      <p class="muted" style="margin-top:10px">Dica: em ataques reais, “notas de resgate” aparecem em várias pastas.</p>
    </div>
  </div>
<script>
  const CODE = "AULA-1234"; // informe aos alunos previamente
  document.getElementById('unlock').onclick = () => {
    const ok = document.getElementById('code').value.trim() === CODE;
    alert(ok ? "Liberado: lembre-se de backups 3-2-1 e MFA." :
               "Código incorreto (DEMO).");
    if (ok) document.getElementById('overlay').style.display = 'none';
  };
</script>
</body>
</html>
```

---

### 2) Mini-lab de criptografia em memória (AES-GCM)
Mostra o “coração” do sequestro (criptografia) sem tocar no disco.  
Instale a lib:
```bash
pip install cryptography
```

**Código (salve como `crypto_lab_memoria.py`):**
```python
import os, json, base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s.encode())

def derivar(senha, sal):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=300_000).derive(senha.encode())

def cifrar(msg, senha):
    sal = os.urandom(16); chave = derivar(senha, sal); gcm = AESGCM(chave); nonce = os.urandom(12)
    ct = gcm.encrypt(nonce, msg.encode(), None)
    return json.dumps({"salt": b64e(sal), "nonce": b64e(nonce), "ct": b64e(ct)}, indent=2)

def decifrar(pkg, senha):
    d = json.loads(pkg); sal, nonce, ct = b64d(d["salt"]), b64d(d["nonce"]), b64d(d["ct"])
    chave = derivar(senha, sal); return AESGCM(chave).decrypt(nonce, ct, None).decode()

if __name__ == "__main__":
    senha = "SenhaDidatica123!"
    pacote = cifrar("Conteúdo SIMULADO (apenas memória).", senha)
    print(">>> CIFRADO:\n", pacote)
    print("\n>>> DECIFRADO:\n", decifrar(pacote, senha))
```

Pontos didáticos: senha → chave (PBKDF2 + sal), nonce único e AEAD (confidencialidade + integridade).

---

### 3) “Backup & Restore” didático (sem código malicioso)
Demonstra o efeito de “dados inacessíveis sem senha” com ferramenta legítima.

**Criar pasta e arquivo (Windows PowerShell / macOS/Linux):**
```powershell
mkdir LAB_SEGURO
"Olá, mundo seguro!" | Out-File -Encoding utf8 LAB_SEGURO\exemplo.txt
```
```bash
mkdir -p LAB_SEGURO && printf "Olá, mundo seguro!\n" > LAB_SEGURO/exemplo.txt
```

**Compactar com senha (7-Zip):**
```powershell
# Windows (ajuste caminho do 7z.exe se necessário)
& "C:\Program Files\7-Zip\7z.exe" a -t7z LAB_ENCRIPTADO.7z ".\LAB_SEGURO\*" -pSenhaDidatica123! -mhe=on
```
```bash
# macOS/Linux (p7zip)
7z a -t7z LAB_ENCRIPTADO.7z ./LAB_SEGURO/* -pSenhaDidatica123! -mhe=on
```

`-mhe=on` protege inclusive nomes de arquivos. Em seguida, descompacte com a senha para demonstrar recuperação.

---

### 4) “Tempestade de arquivos” — log sintético para detectar
Mostra como um SOC/EDR enxerga o surto de mudanças (apenas imprime).

**Salve como `storm_log_sim.py`:**
```python
import time, random, datetime, string
def fake_name():
    base = ''.join(random.choices(string.ascii_lowercase, k=6))
    return f"{base}.docx -> {base}.docx.lock"
for i in range(20):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    print(f"{ts} EVENT=RENAME FILE={fake_name()} PROC=simulador.exe USER=aluno")
    time.sleep(0.1 if i<10 else 0.02)  # acelera para simular “surto”
print("Resumo: pico anômalo de renomeações — indício clássico a ser investigado.")
```

Mensagem: ferramentas de defesa buscam padrões de explosão de I/O e criação de ransom notes.

---

