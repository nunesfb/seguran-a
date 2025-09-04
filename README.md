# 🔹 O que é Malware?

**Malware** vem do termo *"Malicious Software"* (software malicioso).  

É qualquer programa, código ou arquivo criado com o objetivo de **danificar sistemas, roubar informações, comprometer a privacidade, extorquir valores ou causar indisponibilidade de serviços**.  

Ele se diferencia de softwares legítimos porque é intencionalmente projetado para causar prejuízo ou obter vantagem ilícita sobre o usuário ou a organização.  

---

## 🔸 Características principais
- **Intenção maliciosa:** diferente de um bug acidental, o malware é programado para causar dano ou exploração.  
- **Diversas formas:** pode vir em arquivos, scripts, macros, executáveis, até mesmo embutido em hardware ou firmware.  
- **Meios de propagação:** redes sociais, anexos de e-mail, links maliciosos, vulnerabilidades em softwares, dispositivos USB, aplicativos falsos, entre outros.  
- **Efeitos comuns:** roubo de dados, espionagem, lentidão do sistema, perda de arquivos, instalação de backdoors, sequestro de dados (ransomware).  

---

## 🔸 Objetivos do Malware
- **Financeiros:** fraudes bancárias, ransomware, mineração de criptomoedas.  
- **Espionagem:** coleta de dados pessoais, corporativos ou governamentais.  
- **Sabotagem:** derrubar sistemas críticos ou causar indisponibilidade.  
- **Controle:** transformar máquinas em bots para redes de ataques coordenados (botnets).  
- **Engenharia social:** manipular o usuário para instalar softwares falsos ou liberar acesso.  

---

## 🔸 Exemplos práticos de infecção
- Um e-mail com anexo “nota fiscal” que, ao ser aberto, instala um trojan.  
- Um site comprometido que força o download de spyware.  
- Um pen drive infectado que instala um worm automaticamente.  
- Um aplicativo falso na loja de apps que funciona como adware ou keylogger.  

**Em resumo:** todo vírus é um malware, mas nem todo malware é um vírus.  
O termo **malware** é o “guarda-chuva” que engloba **vírus, worms, trojans, ransomware, spyware, adware, rootkits, keyloggers, backdoors**, entre outros.  

---

# 🦠 Vírus

## O que é
Um vírus é um tipo de malware que precisa de um hospedeiro (arquivo, setor de boot ou documento com macro) para replicar-se.  
Ele executa quando o hospedeiro é aberto/executado, tenta infectar outros alvos e, opcionalmente, executa um payload (desde mensagem trivial até sabotagem).

---

## Ciclo de Vida (Conceitual)

- **Execução inicial**: o código é acionado junto do arquivo hospedeiro (ex.: usuário abre o arquivo).  
- **Infecção/replicação**: procura outros alvos compatíveis (arquivos do mesmo formato, documentos, etc.) e injeta uma cópia modificada de si.  
- **Persistência & evasão**: tenta permanecer ativo (chaves de inicialização, tarefas agendadas) e esconder-se (empacotadores, técnicas polimórficas/metamórficas).  
- **Ativação do payload**: com base em um gatilho (data, contagem de execuções, presença de internet), realiza ações planejadas.  
- **Propagação indireta**: a cópia “viaja” quando o arquivo infectado é compartilhado (e-mail, USB, rede, nuvem).

---

## Principais Variantes (Alto Nível)

- **File infector**: injeta código em executáveis/documentos.  
- **Macro vírus**: usa macros (ex.: Office) contidas em documentos.  
- **Boot/MBR**: altera componentes de inicialização do sistema.  
- **Polimórfico/Metamórfico**: muda sua “forma” a cada cópia para dificultar assinaturas.  
  - Polimórfico: cifra/embaralha.  
  - Metamórfico: reescreve partes do próprio código.

---

## Canais de Entrada Mais Comuns

- **Engenharia social**: anexos e links de phishing, “atualizadores” e cracks.  
- **Mídia removível**: USBs e imagens ISO trocadas entre máquinas.  
- **Superfícies expostas**: serviços desatualizados, permissões frouxas, macros habilitadas por padrão.

---

## Linguagens (Contexto Neutro)

Malwares já foram observados em diversas linguagens de propósito geral (C/C++, C#, Go, Rust, Python) e scripting (VBScript, JavaScript/macros).  
**Ponto didático**: não é a linguagem que “faz o vírus”, e sim o comportamento (replicar-se via hospedeiro + executar payload).

---

## IoCs (Indicadores de Comprometimento)

- Arquivos alterados (tamanho/hash divergentes).  
- Macros inesperadas em documentos.  
- Chaves de inicialização/tarefas desconhecidas.  
- Alertas heurísticos do antimalware; travamentos ao abrir certos arquivos.

---

## Mitigação & Resposta

- Desabilitar macros por padrão; somente assinar e habilitar quando necessário.  
- Antimalware/EDR com heurística e bloqueio comportamental.  
- Varredura em **Modo Seguro** e restauração a partir de backups limpos (regra 3-2-1).  
- Allowlisting (AppLocker/WDAC) e bloqueio de autorun em mídias.  
- Treinamento contra phishing/engenharia social.

---

## Demos 100% Seguras para Sala (Sem Malware)

Objetivo: **mostrar conceitos** (replicação, detecção, confidencialidade) **sem criar algo perigoso**.

### 1) Integridade de arquivos com hash (SHA-256)
Demonstra que pequenas mudanças no arquivo geram hash totalmente diferente.  
Exemplo em PowerShell:

```powershell
"Olá, mundo!" | Out-File -Encoding utf8 exemplo.txt
Get-FileHash .\exemplo.txt -Algorithm SHA256
"Linha adicionada." | Add-Content .\exemplo.txt
Get-FileHash .\exemplo.txt -Algorithm SHA256
```

---

### 2) EICAR – teste seguro de antivírus
Arquivo benigno que dispara o antivírus de propósito.

```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Salve como `eicar.txt`. Seu antivírus deve sinalizar.  
⚠️ **Cuidados**: não enviar por e-mail/nuvem institucional.

---

### 3) Mini-lab de Criptografia em Memória (AES-GCM)
Exemplo em Python com `cryptography`:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Exemplo seguro que cifra/decifra apenas texto em memória
```

Mostra: sal + PBKDF2 + nonce + AEAD → confidencialidade e integridade.

---

### 4) Macro Segura (Somente com Clique)
Exemplo simples em Excel/Word:

```vba
Sub ExibirAvisoDidatico()
    MsgBox "DEMO segura: macros podem executar ações quando o usuário clica." & vbCrLf & _
           "Em ambiente real, mantenha macros desabilitadas por padrão.", vbInformation, "DEMO Macro"
End Sub
```

---

### 5) Pasta com Senha (7-Zip)
Demonstra proteção de dados sem risco:

```bash
7z a -t7z LAB_ENCRIPTADO.7z ./LAB_SEGURO/* -pSenhaDidatica123! -mhe=on
```

- `-p`: senha  
- `-mhe=on`: oculta até os nomes dos arquivos

---

# 🪱 Worms — Visão Didática

## O que é
Um **worm** é um malware capaz de **se auto-propagar** pela rede **sem interação do usuário**, explorando **falhas de serviços**, **credenciais fracas** ou **má configuração**. Diferente do vírus, o worm não precisa de um arquivo hospedeiro: ele **escaneia**, **explora** e **se replica** autonomamente, podendo ainda carregar **payloads** (ex.: minerador, ransomware).

---

## Ciclo de Vida (Conceitual)

- **Ponto inicial**: comprometimento de um host (ex.: serviço exposto vulnerável ou RDP com senha fraca).  
- **Descoberta/scan**: varre endereços e portas para **identificar alvos** com o mesmo ponto fraco.  
- **Exploração & queda de payload**: usa a falha para ganhar execução remota e **implanta** seu componente.  
- **Replicação**: o novo host comprometido **repete o processo** (efeito cascata).  
- **Persistência/controle (opcional)**: cria serviço/tarefa, ajusta chaves de inicialização e, às vezes, contata C2.  
- **Ação/payload**: criptomineração, DDoS, exfiltração ou “worm-ransomware” (ex.: casos “wormáveis”).

---

## Principais Variantes (Alto Nível)

- **Network worms**: exploram **serviços de rede** (SMB/RPC/HTTP/RDP) para se espalhar.  
- **E-mail/IM worms (históricos)**: usam catálogos de contatos para enviar cópias de si mesmos.  
- **USB/Removable worms**: propagação por **mídias removíveis** e autorun (ou falhas de atalho/LNK).  
- **IoT worms**: miram dispositivos com **senhas padrão** e serviços expostos (ex.: Telnet/HTTP).  
- **Worm-ransomware**: combinação de propagação automática + criptografia de arquivos.  

---

## Canais de Entrada Mais Comuns

- **Serviços expostos** sem patch (SMB, RDP, HTTP, bases de dados).  
- **Credenciais fracas** ou reutilizadas (brute force/credential stuffing).  
- **IoT desatualizado** com senhas de fábrica.  
- **Compartilhamentos internos** permissivos e redes planas (sem segmentação).

---

## Linguagens (Contexto Neutro)
Worms já foram observados em **C/C++** (baixo nível, sockets), **Go/Rust** (binários estáticos, multiplataforma) e **scripts** como **PowerShell**/Python (automação em ambientes Windows/Linux). **Ponto didático**: a linguagem não define a ameaça — o **comportamento auto-propagante** é o essencial.

---

## IoCs (Indicadores de Comprometimento)

- **Picos de varredura** (muitos destinos/portas em curto intervalo).  
- **Aumentos de falhas de autenticação** e criação de contas/serviços inesperados.  
- **Conexões laterais incomuns** (leste-oeste) e novos **processos em massa**.  
- **Alterações de firewall/registro** e **tarefas agendadas** recém-criadas.  

---

## Mitigação & Resposta

- **Patching acelerado** (priorize CVEs explorados ativamente); **desativar legados** (ex.: SMBv1).  
- **Segmentação de rede/VLAN**, **ACLs** e **controle de egress** (saídas restritas).  
- **MFA** e políticas de senha; **fechar RDP** à internet (ou túnel/VPN com MFA).  
- **EDR/IDS/IPS** com detecção de varredura e exploração; **honeypots** internos para alerta precoce.  
- **Contenção rápida**: isolar host, bloquear indicadores, revogar credenciais, varrer lateralidade.  
- **Backups 3-2-1** testados e **exercícios de resposta** (tabletop + playbooks).

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: ilustrar **propagação**, **detecção** e **segmentação** sem tocar na rede real ou explorar falhas.

### 1) Simulador de Propagação “em Memória”
Demonstra o efeito cascata sem rede, apenas com “hosts” fictícios.

```python
# Simulação didática (offline): propagação tipo S-I em uma rede fictícia.
# Não faz conexões reais. Requer Python 3.x.
import random

N = 40                      # "hosts" fictícios
edges = {i:set() for i in range(N)}
# Gera "rede" aleatória e esparsa
for i in range(N):
    for j in range(i+1, N):
        if random.random() < 0.07:
            edges[i].add(j); edges[j].add(i)

infected = {0}              # ponto inicial
steps = 0
print(f"Passo {steps}: infectados={sorted(infected)}")

while True:
    steps += 1
    new_inf = set()
    for h in infected:
        for viz in edges[h]:
            # "Explorar" com chance p (representa serviço vulnerável)
            if viz not in infected and random.random() < 0.35:
                new_inf.add(viz)
    if not new_inf:
        break
    infected |= new_inf
    print(f"Passo {steps}: +{sorted(new_inf)}  total={len(infected)}")

print("\nResumo: propagação terminou. Total infectado (fictício) =", len(infected))
```

Explique: cada “aresta” representa possibilidade de alcance; a probabilidade simula “vulnerável vs. corrigido”. Mostra a dinâmica de espalhamento sem qualquer risco.

---

### 2) Logs Sintéticos de Varredura + Detecção
Gere um “log” fictício e mostre como um SOC acharia padrões.

```text
2025-09-03T14:10:01 SRC=10.0.1.23 DST=10.0.1.101 DPT=445 RESULT=REFUSED
2025-09-03T14:10:01 SRC=10.0.1.23 DST=10.0.1.102 DPT=445 RESULT=REFUSED
2025-09-03T14:10:02 SRC=10.0.1.23 DST=10.0.1.103 DPT=445 RESULT=ACCEPT
2025-09-03T14:10:02 SRC=10.0.1.23 DST=10.0.1.104 DPT=3389 RESULT=REFUSED
2025-09-03T14:10:03 SRC=10.0.1.23 DST=10.0.1.105 DPT=445 RESULT=ACCEPT
```

Exercício (conceitual): peça para os alunos contarem destinos por porta e marcarem host com padrão de varredura (muitos destinos/mesma porta em janela curta).

---

### 3) Segmentação Visual (Quadro/Slide)
Desenhe 3 VLANs (Usuários/Servidores/IoT) e trace ACLs mínimas (ex.: Usuários → HTTP/HTTPS de saída; IoT sem saída para internet; Admin via jump-host).  
Mensagem: redes planas aceleram worms; segmentação reduz o raio de explosão.

---

### 4) “Antes/Depois do Patch” (Exercício guiado)
Crie um quadro com duas colunas:

- **Antes**: serviço desatualizado exposto, pico de falhas de login, conexões em 445.  
- **Depois**: porta filtrada, MFA em RDP, redução de alertas.  

Discussão: priorização de patches e janela de manutenção.

---  

# 🐴 Trojan (Cavalo de Troia) — Visão Didática

## O que é
Um **Trojan** é um malware que **se disfarça de software legítimo** (instalador, plugin, “atualizador”, crack) para que o usuário **execute** o programa e, então, **instale um payload** (ex.: RAT, ladrão de senhas, downloader). Normalmente ele busca **persistência** e pode se comunicar com um **C2 (Command & Control)**.

---

## Ciclo de Vida (Conceitual)

- **Entrega/Engano (masquerade)**: chega por *phishing*, site de downloads, malvertising, “atualizador” falso, app *sideloaded*.  
- **Execução**: o usuário roda o executável/instalador acreditando ser legítimo.  
- **Queda de payload**: baixa (“downloader”) ou solta (“dropper”) componentes adicionais.  
- **Persistência & evasão**: cria tarefas/serviços/chaves de inicialização; usa empacotadores e ofuscação.  
- **Comunicação (C2)**: tenta contatar domínios/IPs para receber comandos e exfiltrar dados.  
- **Ação**: espionagem (RAT), furto de credenciais (infostealer), movimentação lateral, etc.

---

## Principais Variantes (Alto Nível)

- **Dropper / Downloader**: entrega/baixa outros malwares.  
- **RAT (Remote Access Trojan)**: controle remoto e espionagem.  
- **Banker / Infostealer**: roubo de credenciais, cookies, cofres.  
- **Fake Updater / Fake Installer**: imita atualizações/instaladores.  
- **Supply-chain / Typosquatting**: pacote dependência malicioso ou nome quase igual (ex.: `reqeusts` vs `requests`).  

---

## Vetores Comuns

- **Phishing** com anexos/links.  
- **Cracks/warez** e instaladores de procedência duvidosa.  
- **Malvertising** (anúncios que levam a downloads falsos).  
- **Sideloading** de apps fora de lojas oficiais.  

---

## IoCs (Indicadores de Comprometimento)

- **Processos desconhecidos** fazendo **beaconing** (conexões periódicas) para **domínios recém-registrados**.  
- **Serviços/Tarefas agendadas** inesperados; chaves *Run*/*RunOnce* novas.  
- **Arquivos/DLLs** suspeitos lado a lado com apps legítimos (busca de DLL por ordem de carga).  
- **Exfiltração** (tráfego a *pastebins*, encurtadores) e alterações em políticas do navegador.

---

## Mitigação & Resposta

- **Privilégios mínimos** (usuários sem admin); **MFA** e **Allowlisting** (AppLocker/WDAC).  
- **Bloquear software não assinado** e **verificar assinaturas/hashes** de binários.  
- **EDR/XDR** com regras de **beaconing**, *child-process* suspeitos e *script-blocking*.  
- **Isolamento** rápido do host, revogação de credenciais, varredura de persistência e restauração a partir de **backups limpos**.

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: **mostrar o conceito** de “Trojan” (disfarce, confiança, persistência, beaconing) **sem** criar nada perigoso.

### 1) “Instalador” enganoso (apenas UI educativa)
Mostra como a interface poderia enganar — **sem baixar/instalar nada**. Ao clicar, revela que seria um Trojan.

Salve como `trojan_ui_demo.html` e abra no navegador.
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>[DEMO] Instalador Falso (educativo)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0c111b;color:#e7ebf3;display:grid;place-items:center;min-height:100dvh;margin:0}
    .card{background:#141a2b;border:1px solid #26324a;border-radius:16px;padding:24px;max-width:560px;width:clamp(320px,90vw,560px);box-shadow:0 8px 30px rgba(0,0,0,.35)}
    h1{margin:0 0 8px} .muted{color:#9fb1d1}
    button{border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer;background:#4f7cff;color:#fff}
    ul{margin-top:8px}
  </style>
</head>
<body>
  <div class="card">
    <h1>Instalador do “SuperPlayer Pro”</h1>
    <p class="muted">*DEMONSTRAÇÃO DIDÁTICA — não instala nada*</p>
    <ul>
      <li>Versão: 10.4</li>
      <li>Editora: SuperSoft LLC (não verificado)</li>
      <li>Tamanho: 2.1 MB</li>
    </ul>
    <button id="instalar">Instalar</button>
    <p id="nota" class="muted" style="margin-top:12px;"></p>
  </div>
  <script>
    document.getElementById('instalar').onclick = () => {
      alert("Se fosse um Trojan, este botão instalaria um payload oculto (RAT/stealer) e criaria persistência.\nAqui é apenas uma DEMO segura.");
      document.getElementById('nota').textContent =
        "Dica: verifique assinatura digital, hash, origem do download e políticas de allowlisting.";
    };
  </script>
</body>
</html>
```

---

### 2) Verificação de Assinatura e Hash (defensivo)
Demonstre que binários legítimos devem ter assinatura válida e hash verificável.

**Windows (PowerShell):**
```powershell
# Hash do arquivo
Get-FileHash "C:\caminho\para\aplicativo.exe" -Algorithm SHA256

# Assinatura Authenticode
Get-AuthenticodeSignature "C:\caminho\para\aplicativo.exe" | Format-List *
```

**macOS:**
```bash
# Hash
shasum -a 256 /caminho/Aplicativo.app/Contents/MacOS/Aplicativo

# Assinatura
codesign --verify --deep --strict --verbose=4 /caminho/Aplicativo.app
```

**Linux:**
```bash
sha256sum /caminho/aplicativo
# (Se fornecido pelo fornecedor) gpg --verify assinatura.asc aplicativo
```

Mensagem didática: “Trojan” típico não possui assinatura confiável e muitas vezes vem de fonte sem cadeia de confiança.

---

### 3) “Beaconing” offline (simulação segura)
Simule o comportamento de conexões periódicas sem usar rede: o script apenas imprime que “beaconaria”.

Salve como `beacon_sim.py` e execute com `python beacon_sim.py`.

```python
# DEMO segura: simula "beaconing" sem rede (apenas prints)
import time, uuid, random, datetime

HOST_ID = str(uuid.uuid4())[:8]
C2 = "c2.exemplo-inofensivo.local"  # NÃO é resolvido/contatado
intervalo = (5, 9)  # segundos

print(f"[start] host={HOST_ID} simulando beacon para {C2}")
for i in range(5):  # 5 ciclos apenas
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    print(f"[{ts}] beacon -> {C2} (simulado) payload={{host:'{HOST_ID}', seq:{i}}}")
    time.sleep(random.randint(*intervalo))
print("[done] fim da simulação")
```

Explique: EDR procura padrões periódicos e domínios recentes. Em ambiente real, bloquearia no proxy/Firewall e alertaria.

---

### 4) Inventário de Persistência (somente leitura)
Liste locais típicos onde Trojans tentam persistir — sem criar nada.

**Windows (PowerShell):**
```powershell
# Tarefas agendadas
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Sort-Object TaskPath,TaskName

# Itens de inicialização (usuário)
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location

# Chaves Run/RunOnce (apenas leitura)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Linux:**
```bash
# Cron do usuário e do sistema
crontab -l 2>/dev/null || echo "sem crontab do usuário"
ls -al /etc/cron.* /etc/cron.d 2>/dev/null

# Autostart por sessão
ls -al ~/.config/autostart 2>/dev/null

# Serviços e timers
systemctl list-timers --all
systemctl list-units --type=service --state=running
```

**macOS:**
```bash
# LaunchAgents/Daemons
ls -al ~/Library/LaunchAgents
ls -al /Library/LaunchAgents
ls -al /Library/LaunchDaemons

# Itens de login (Ventura+)
osascript -e 'tell application "System Events" to get the name of every login item'
```

Exercício: peça aos alunos para identificar entradas desconhecidas e discutir critérios de suspeição (nome, pasta, editor, data, assinatura).

---

## Roteiro Sugerido (20–25 min)
- **Conceito & ciclo de vida** (5 min).  
- **UI do “instalador” falso** (3–5 min) → reforçar “não instale de fontes não confiáveis”.  
- **Assinatura & hash** (5–7 min) → verificação prática.  
- **Beaconing offline** (3–5 min) → como o SOC/EDR detectaria.  
- **Persistência (inventário)** (3–5 min) → onde caçar IoCs.

-----

# 🕵️ Spyware — Visão Didática

## O que é
**Spyware** é um tipo de malware focado em **coletar informações sem consentimento** — histórico de navegação, cookies/sessões, credenciais salvas, capturas de tela, localização, telemetria do dispositivo etc.  
Em geral, atua silenciosamente, priorizando **persistência** e **exfiltração** (envio de dados) para um servidor do atacante.

---

## Como funciona (alto nível)
- **Coleta**: lê/copia dados sensíveis (cookies, “auto-fill”, cofres do navegador), faz **screenshots**, registra eventos (p. ex., “form-grabbing” no navegador).  
- **Persistência**: adiciona-se a **tarefas agendadas**, chaves de **Run/RunOnce**, **LaunchAgents/Daemons**, *autostart* etc.  
- **Evasão**: ofuscação, *packing*, uso de processos legítimos (navegador, PowerShell), tentativas de desativar AV/EDR.  
- **Exfiltração**: envia dados para **C2** ou serviços públicos (*pastebins*, encurtadores) usando HTTP(S), DNS tunneling ou APIs.

---

## Principais variantes (alto nível)
- **Infostealer**: foca em **cookies/sessões**, senhas salvas, carteiras cripto.  
- **Banker**: fraudes financeiras (injeção de páginas, *overlays*).  
- **Stalkerware**: monitora localização/comunicações (geralmente em mobile).  
- **Ad/Trackingware agressivo**: coleta extensiva para anúncios/perfis.  
- **Fileless**: opera em **memória** e abusa de ferramentas legítimas (PowerShell/WMI).

---

## Vetores comuns
- **Anexos maliciosos** (phishing) e downloads “gratuitos” (*bundlers* com *adware/spyware*).  
- **Extensões de navegador** com permissões excessivas.  
- **Sites comprometidos / malvertising** (scripts de terceiros).  
- **Software pirata** e “atualizadores” falsos.

---

## IoCs (Indicadores de Comprometimento)
- **Extensões suspeitas** instaladas recentemente; permissões amplas (“Ler e alterar dados de todos os sites”).  
- **Tráfego** para **pastebins**, encurtadores, domínios recém-registrados ou picos de **exfiltração** fora do horário.  
- **Certificados raiz novos** (tentativa de interceptar HTTPS via *man-in-the-browser / proxy*).  
- **Mudanças** em políticas do navegador, novos **processos/tarefas** persistentes, chaves de inicialização.

---

## Mitigação & Resposta
- **Endurecer navegadores**: bloquear extensões não aprovadas (lista de permissão), desabilitar *autofill* para senhas sensíveis, bloquear *third-party cookies* onde possível.  
- **Gerenciadores de senhas + MFA**: não salve senhas no navegador sem política; prefira **cofres** e **chaves físicas/U2F**.  
- **EDR/XDR + proxy seguro**: detectar **beaconing/exfiltração** e bloquear domínios recém-criados.  
- **Revisar certificados raiz**: remover CA não autorizada; usar **pinning** em apps críticos.  
- **Resposta**: isolar host, invalidar sessões, **rotacionar credenciais**, revisar perfil do navegador, remover extensões suspeitas, checar persistência, **lições aprendidas**.

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: **entender o conceito** de coleta e exfiltração **sem capturar dados reais**, sem rede e sem tocar no sistema.

### 1) Permissões do navegador (Geolocalização com consentimento explícito)
Mostra como um site **pode solicitar localização** — aqui só exibe na tela, **não envia nada**.

Salve como `demo_geoloc.html`:
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>[DEMO] Permissão de geolocalização (segura)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body{font-family:system-ui;background:#0c111b;color:#e7ebf3;display:grid;place-items:center;min-height:100vh}
  .card{background:#141a2b;border:1px solid #26324a;border-radius:16px;padding:24px;max-width:540px}button{padding:10px 14px;border:0;border-radius:10px;background:#4f7cff;color:#fff;font-weight:700;cursor:pointer}</style>
</head>
<body>
  <div class="card">
    <h1>DEMO — Solicitação de Localização</h1>
    <p>Ao clicar, o navegador pedirá <strong>permissão</strong>. O resultado aparece abaixo (nada é enviado).</p>
    <button id="pedir">Solicitar localização</button>
    <pre id="out"></pre>
  </div>
  <script>
    const out = document.getElementById('out');
    document.getElementById('pedir').onclick = async () => {
      if(!('geolocation' in navigator)) { out.textContent = 'Sem API de geolocalização.'; return; }
      navigator.geolocation.getCurrentPosition(
        pos => out.textContent = JSON.stringify({
          latitude: pos.coords.latitude.toFixed(5),
          longitude: pos.coords.longitude.toFixed(5),
          precisao_m: pos.coords.accuracy
        }, null, 2),
        err => out.textContent = 'Permissão negada (boa prática quando você não confia no site).'
      );
    };
  </script>
</body>
</html>
```

Mensagem didática: “Permissões são poderosas; conceda apenas ao que for necessário e a sites confiáveis.”

---

### 2) “Exfiltração” offline (simulação com redação/anônimo)
Demonstra que um script poderia preparar dados para envio; aqui nada sai do navegador.
Ele anonimiza padrões sensíveis (e-mail, CPF fictício) e apenas mostra o JSON que “seria” enviado.

Salve como `demo_exfil_offline.html`:
```html
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><title>[DEMO] Exfiltração (simulada, offline)</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui;background:#0b1220;color:#e7eaf3;display:grid;place-items:center;min-height:100vh}
.card{background:#141b2d;border:1px solid #26324a;border-radius:16px;padding:24px;max-width:720px;width:clamp(320px,90vw,720px)}
textarea{width:100%;min-height:120px;border-radius:10px;border:1px solid #2f3d5a;background:#0f1626;color:#e7eaf3;padding:12px}
button{margin-top:12px;padding:10px 14px;border:0;border-radius:10px;background:#4f7cff;color:#fff;font-weight:700;cursor:pointer}
pre{background:#10172b;border:1px solid #26324a;border-radius:10px;padding:12px;overflow:auto}</style>
</head>
<body>
  <div class="card">
    <h1>DEMO — Preparação de “exfiltração” (apenas exibe, não envia)</h1>
    <p>Digite dados <strong>fictícios</strong> abaixo. O script <em>redige</em> e <strong>mostra</strong> o JSON que um spyware enviaria — mas aqui fica <strong>só na tela</strong>.</p>
    <textarea id="txt" placeholder="Ex.: Meu e-mail é joao@example.com e meu CPF é 123.456.789-09 (fictício)."></textarea>
    <button id="prep">Preparar pacote</button>
    <pre id="out"></pre>
  </div>
<script>
function redact(s){
  const email=/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  const cpf=/\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/g; // demonstração
  return s.replace(email,'<email>').replace(cpf,'<cpf>');
}
document.getElementById('prep').onclick=()=>{
  const raw=document.getElementById('txt').value;
  const red=redact(raw);
  const pacote={
    timestamp:new Date().toISOString(),
    origem:"pagina_demo_local",
    dados_anonimizados:red,
    observacao:"DEMO offline — nenhum envio de rede ocorre aqui."
  };
  document.getElementById('out').textContent=JSON.stringify(pacote,null,2);
};
</script>
</body>
</html>
```

Mensagem didática: “Exfiltração é trivial quando um script tem acesso; DLP/EDR e políticas de conteúdo (CSP) reduzem risco.”

---

### 3) Revisão de extensões (passo a passo — sem código)
Mostre aos alunos como auditar permissões:

- **Chrome/Edge**: abra `chrome://extensions` / `edge://extensions` → Detalhes → verifique Permissões (“Ler e alterar dados de todos os sites?”) e Fonte (loja oficial, editor verificado).  
- **Firefox**: `about:addons` → Extensões → Permissões.  

Boas práticas: remova extensões que não usa, desconfie de mudanças recentes de editor, bloqueie por política em ambientes corporativos.

---

### 4) Checagem de certificados raiz (somente leitura)
Detectar CA não autorizada ajuda a evitar interceptação do HTTPS por malware.

**Windows (PowerShell):**
```powershell
# Listar Autoridades Raiz (LocalMachine)
Get-ChildItem Cert:\LocalMachine\Root | Select-Object Subject, Thumbprint, NotBefore, NotAfter | Sort-Object Subject

# Raiz do Usuário Atual
Get-ChildItem Cert:\CurrentUser\Root | Select-Object Subject, Thumbprint, NotBefore, NotAfter
```

**macOS:**
```bash
# Listar âncoras do sistema
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain | openssl x509 -noout -subject -enddate | head
# Keychain do usuário (inspecione no app "Acesso às Chaves" para ver emissores recentes)
```

**Linux (Ubuntu/Debian):**
```bash
ls -l /usr/share/ca-certificates
sudo update-ca-certificates --fresh  # (apenas para reconstruir a store, sem adicionar CAs)
```

O que observar: CAs recém-adicionadas por softwares desconhecidos. Em empresas, siga o processo formal antes de remover entradas.

---

## Dicas de condução (defensivo)
- Reforce MFA e cofres de senha (reduzem impacto de roubo de cookies/senhas).  
- CSP/SRI: políticas de conteúdo e integridade de scripts limitam dano de terceiros.  
- Proxy seguro/Firewall: bloqueie domínios de exfiltração e domínios recém-registrados.  
- Treinamento: cuidado com anexos e instaladores “grátis”; verifique assinatura digital e hash de mídias.

 -----

# 📢 Adware — Visão Didática

## O que é
**Adware** é um software indesejado que **injeta propagandas**, altera **página inicial** e **mecanismos de busca**, cria **redirecionamentos** e, em alguns casos, atua como **porta de entrada** para outras ameaças (downloader).

---

## Como funciona (alto nível)
- **Instalação oportunista:** vem “de brinde” em **bundlers** (instaladores de freeware com ofertas pré-marcadas) ou extensões de navegador com **permissões excessivas**.  
- **Alteração do navegador:** troca **home page**, **search engine**, adiciona **extensões** e scripts de **injeção de anúncios**.  
- **Persistência & evasão:** recria tarefas/serviços após remoção, reinjeta configurações no perfil do navegador.  
- **Monetização:** paga por **impressões/cliques** (às vezes via redes de **malvertising**).  

---

## Principais variantes (alto nível)
- **Browser hijacker:** sequestra busca e página inicial.  
- **Ad injector:** insere banners/pop-ups/overlays em sites.  
- **PUP/PUA (aplicativo potencialmente indesejado):** “otimizadores/limpadores” que forçam anúncios.  
- **Bundled installers:** empacotam várias “ofertas” e restauram o adware ao reiniciar.

---

## Vetores comuns
- **Instaladores “free”/bundlers** com opções escondidas.  
- **Sites de *warez*/cracks** e “atualizadores” falsos.  
- **Extensões** de navegador pouco confiáveis.  
- **Campanhas de malvertising** (anúncios que levam a download suspeito).

---

## IoCs (Indicadores de Comprometimento)
- **Pop-ups** e **redirecionamentos** frequentes sem motivo.  
- **Home page/search engine** modificados sem consentimento.  
- **Extensões/serviços** desconhecidos que **reaparecem** após remoção.  
- **Tarefas agendadas** recriando o adware; novos **parâmetros** de inicialização do navegador (ex.: `--load-extension=...`).  

---

## Mitigação & Resposta
- **Restauração do navegador**: redefinir configurações, remover **extensões** não aprovadas, limpar **atalhos**/parâmetros de execução.  
- **Bloqueio de bundlers**: **allowlisting** de software (AppLocker/WDAC) e instalação apenas via **lojas oficiais**.  
- **Varredura antimalware/EDR** e revisão de **tarefas agendadas**/itens de inicialização.  
- **Políticas corporativas**: catálogo de extensões permitidas, bloqueio de malvertising, educação do usuário (“desmarcar ofertas”).  

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: mostrar **efeitos irritantes** do adware **sem instalar nada**, **sem persistência** e **sem tocar no sistema**.

### 1) “Adware” inofensivo (apenas nesta página)
Salve como `adware_demo.html` e abra no navegador.

```html
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<title>[DEMO DIDÁTICA] Adware</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root{--bg:#0e0f13;--fg:#e9ecf1;--mut:#a8b0bf;--accent:#ff4757}
  body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif}
  header{padding:20px;border-bottom:1px solid #232631}
  main{padding:24px;max-width:900px;margin:0 auto}
  button{border:0;border-radius:10px;padding:10px 14px;font-weight:600;cursor:pointer}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .banner{position:fixed;left:12px;bottom:12px;background:#ffeaa7;color:#111;padding:10px 14px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
  .ad{position:fixed;background:#1b1e2a;border:1px solid #30364a;color:#e9ecf1;border-radius:14px;box-shadow:0 16px 42px rgba(0,0,0,.5);width:280px;padding:14px}
  .ad h3{margin:0 0 6px}
  .muted{color:var(--mut)}
  .close{float:right;background:var(--accent);color:#fff;border-radius:8px;padding:4px 8px}
</style>
</head>
<body>
  <header>
    <h1>DEMO: Comportamento “Adware” (inofensivo)</h1>
    <p class="muted">Banners invasivos e “alteração” de homepage — <strong>apenas nesta página</strong>.</p>
  </header>

  <main>
    <div class="row">
      <button id="spawn">Gerar anúncio</button>
      <button id="spawnMany">Gerar vários</button>
      <button id="clearAll">Remover todos</button>
      <button id="toggleHome">Alterar “página inicial” (falso)</button>
    </div>
    <p style="margin-top:18px;color:var(--muted)">Simulação didática — nada é instalado e nada persiste.</p>
  </main>

  <div class="banner" id="banner" hidden>
    “Sua página inicial foi alterada!” (mentira típica de adware) — <button id="undo">Desfazer</button>
  </div>

  <script>
    let count = 0;
    function createAd(x=20,y=80){
      const ad = document.createElement('div');
      ad.className = 'ad';
      ad.style.left = (x + Math.random()*40) + 'px';
      ad.style.top  = (y + Math.random()*40) + 'px';
      ad.style.zIndex = 1000 + count++;
      ad.innerHTML = `
        <button class="close" aria-label="Fechar">x</button>
        <h3>Promoção Imperdível!</h3>
        <p class="muted">Clique aqui! Clique aqui! Clique aqui!</p>
      `;
      ad.querySelector('.close').onclick = () => ad.remove();
      ad.onmousedown = (e) => { // arrastar
        const dx = e.clientX - ad.offsetLeft, dy = e.clientY - ad.offsetTop;
        function move(ev){ad.style.left=(ev.clientX-dx)+'px';ad.style.top=(ev.clientY-dy)+'px';}
        function up(){window.removeEventListener('mousemove',move);window.removeEventListener('mouseup',up);}
        window.addEventListener('mousemove',move);window.addEventListener('mouseup',up);
      };
      document.body.appendChild(ad);
    }
    document.getElementById('spawn').onclick = ()=> createAd(40,120);
    document.getElementById('spawnMany').onclick = ()=> { for(let i=0;i<4;i++) createAd(60+i*40,140+i*30); };
    document.getElementById('clearAll').onclick = ()=> document.querySelectorAll('.ad').forEach(e=>e.remove());
    document.getElementById('toggleHome').onclick = ()=> document.getElementById('banner').hidden = false;
    document.getElementById('undo').onclick = ()=> document.getElementById('banner').hidden = true;
  </script>
</body>
</html>
```

**Pontos didáticos para narrar durante a demo**
- Como extensões/scripts poderiam injetar banners e “forçar” homepage/search.  
- Por que listas de permissão (allowlist) de extensões e instalação centralizada reduzem o risco.  
- Diferença entre adware (irritante/indesejado) e malvertising (anúncio que leva a malware).

---

### 2) Checklist de Remediação (prática rápida)
- **Navegador**: redefinir configurações, remover extensões suspeitas, revisar atalhos (parâmetros).  
- **Sistema**: verificar tarefas agendadas/itens de inicialização; rodar antimalware/EDR.  
- **Política**: bloquear bundlers e só permitir software/lojas confiáveis; catálogo de extensões aprovadas.

 -----

# 🪤 Rootkits — Visão Didática

## O que é
**Rootkits** são conjuntos de técnicas/softwares voltados a **ocultar** processos, arquivos, chaves de registro e conexões, garantindo **persistência** e **evasão** da detecção. Podem atuar em **modo usuário**, **kernel**, **boot/firmware** (UEFI) e até em **dispositivos** (placas/BIOS).

---

## Como funciona (alto nível)
- **Cloaking (ocultação):** “enganam” ferramentas do sistema (listas de arquivos/processos/drivers), interceptando chamadas de API para **não mostrar** o que o atacante quer esconder.  
- **Persistência:** serviços/tarefas, chaves de inicialização, *launch agents/daemons*, modificação de **boot chain** ou **firmware**.  
- **Evasão:** assinaturas digitais indevidas, ofuscação, uso de drivers vulneráveis/ilegítimos, desativação de logs/telemetria.  
- **Controle:** podem abrir backdoors, exfiltrar dados, carregar outros malwares de forma furtiva.

---

## Principais variantes (alto nível)
- **User-mode rootkit:** intercepta APIs em processos de usuário (ex.: *hook* em funções de listagem).  
- **Kernel-mode rootkit:** carrega **driver** que altera tabelas/rotinas do kernel (ocultação mais profunda).  
- **Bootkit/UEFI:** compromete **bootloader**/NVRAM/firmware para executar **antes** do SO.  
- **Firmware/Device rootkit:** embutido em controladoras, NIC, GPU etc. (mais raro e avançado).

---

## Vetores comuns
- **Exploração de kernel/drivers** (EoP), **drivers comprometidos** (assinados ou *bring-your-own-vulnerable-driver*).  
- **Boot adulterado** (desativar **Secure Boot**, manipular UEFI).  
- **Pós-exploração** após phishing/exploit (o rootkit é instalado para **permanecer** e ocultar).

---

## IoCs (Indicadores de Comprometimento)
- **Divergências de visão**: ferramenta A não vê arquivos/processos que ferramenta B vê.  
- **Secure Boot desativado** repentinamente; logs de **Code Integrity** acusando falhas.  
- **Drivers suspeitos** carregados recentemente; mensagens de “módulo não verificado” no *kernel log*.  
- **Alterações** de NVRAM/boot entries; políticas do EDR desabilitadas sem justificativa.

---

## Mitigação & Resposta
- **Prevenção:** **Secure Boot/Measured Boot/TPM** habilitados; **allowlisting** de drivers; manter SO/firmware **atualizados**.  
- **Detecção:** EDR/XDR com **verificação de integridade**, varredura fora de banda (rescue mídia), comparação de **visões** (user vs. baixo nível).  
- **Resposta:** **isolar** o host, **preservar evidências** (memória/logs), **reprovisionar** com **mídia confiável** (reinstalação limpa), **rotacionar segredos**; revisar cadeia de boot/firmware.

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: ilustrar **ocultação** e **divergência de visão**, **assinatura/verificação de drivers** e **estado do Secure Boot**, sem tocar em kernel, boot ou firmware.

### 1) “Cloaking” simulado (apenas no script)
Mostra a ideia de “ferramenta enganada”: um script “lista” arquivos, mas **filtra** um nome — e depois você compara com a listagem real do SO.

Salve como `rootkit_cloak_sim.py`:
```python
# DEMO segura: simula uma ferramenta "enganada" que oculta nomes contendo "secreto"
import os, sys
p = sys.argv[1] if len(sys.argv) > 1 else "."
real = sorted(os.listdir(p))
fake = [f for f in real if "secreto" not in f.lower()]

print("Visão (ferramenta enganada):", fake)
print("Visão real (SO):            ", real)
print("\nExperimente criar 'secreto.txt' e rodar novamente.")
```

**Uso:**
```bash
mkdir -p LAB_ROOTKIT && cd LAB_ROOTKIT
echo ok > normal.txt
echo oculto > secreto.txt
python3 ../rootkit_cloak_sim.py .
ls -la   # compare com a saída do script
```

Mensagem didática: rootkits de verdade fazem algo análogo, porém dentro do sistema (user/kernel), enganando utilitários.

---

### 2) Verificar Secure Boot (somente leitura)
**Windows (PowerShell, admin):**
```powershell
Confirm-SecureBootUEFI
# True = habilitado; False = desabilitado (ou BIOS legado)
```

**Linux:**
```bash
mokutil --sb-state     # em distros com shim/EFI
bootctl status         # em sistemas com systemd-boot
dmesg | grep -i secure # mensagens do kernel sobre Secure Boot
```

**macOS:**
- SIP (proteção de integridade): `csrutil status` (leitura).  
- Secure Boot (Apple Silicon/T2): checado pela “Utilitário de Segurança de Inicialização” no modo de recuperação (somente verificar, não alterar, em aula).

Mensagem: Boot verificado dificulta bootkits e drivers não confiáveis.

---

### 3) Inventário de drivers/módulos (somente leitura)
**Windows:**
```powershell
# Listar drivers e verificar assinatura Authenticode
Get-ChildItem C:\Windows\System32\drivers\*.sys |
  Get-AuthenticodeSignature |
  Select-Object Path, Status, SignerCertificate | Format-Table -AutoSize

# Listar drivers carregados
driverquery /v /fo table
```

**Linux:**
```bash
lsmod | head
# Ver assinante de um módulo (se suportado)
modinfo -F signer <nome_do_modulo>
dmesg | egrep -i "module|taint|verif" | tail -n 50
```

**macOS (moderno):**
```bash
kmutil showloaded | head   # módulos/kexts carregados (em versões recentes)
```

Mensagem: drivers não assinados ou recém-adicionados sem mudança planejada são sinais de alerta.

---

### 4) Comparação de “duas visões” (exercício rápido)
Rode o script do item 1 para ver ocultação simulada.  
Em seguida, use ferramentas do SO (`ls/dir`, Task Manager/Activity Monitor/`ps`) para comparar.  

Discussão: por que EDR costuma fazer verificação fora de banda (kernel callbacks, raw reads) para confirmar?

---

## Dicas de condução (defensivo)
- Reforce política de drivers (allowlisting, atualização, remoção de legado).  
- Monitorar mudanças de boot (Secure Boot, chaves MOK, UEFI updates).  
- Treinar equipe a reconhecer divergência de visão (ex.: “minha ferramenta não vê, mas o sistema vê”).  
- Encerrar com procedimento de erradicação: quando suspeitar de rootkit em kernel/boot, reinstale limpo a partir de mídia confiável e troque credenciais.

--------

# ⌨️ Keyloggers — Visão Didática

## O que é
**Keyloggers** são ferramentas (software ou hardware) que **capturam eventos de teclado** e, às vezes, **dados de formulários** e **telas**. O objetivo típico é **roubar credenciais** e outras informações sensíveis. Em contexto malicioso, costumam **persistir** e **exfiltrar** dados para um servidor do atacante.

---

## Como funciona (alto nível)
- **Captura**: observa pressionamentos de teclas (**keydown/keyup**) ou lê campos de formulário antes do envio. Variantes avançadas podem **gravar tela**/clipboard.
- **Persistência** (software): tarefas agendadas, chaves de *Run*/serviços, extensões do navegador.
- **Evasão**: ofuscação, injeção de DLL, uso de processos legítimos (navegador/PowerShell).
- **Exfiltração**: envio periódico (“**beaconing**”) a **C2**; às vezes via serviços públicos (*pastebins*).

---

## Principais variantes (alto nível)
- **Software (aplicação/driver)**  
  - *In-browser/form-grabber*: scripts/ extensões que leem campos **dentro do navegador**.  
  - *User-mode hooks*: “enganam” APIs de entrada em processos de usuário.  
  - *Kernel drivers*: capturam no nível do sistema (maior privilégio).  
  - *Screen/clipboard loggers*: complementam com captura de tela/área de transferência.
- **Hardware**  
  - **Dispositivos USB inline** (entre teclado e PC).  
  - **Teclados adulterados** com memória interna.

---

## Vetores comuns
- **Trojans/phishing** (anexos e instaladores falsos).  
- **Extensões de navegador** com **permissões amplas**.  
- **Dispositivos USB** adulterados/“brindes”.

---

## IoCs (Indicadores de Comprometimento)
- **DLLs injetadas** em navegadores/Apps de escritório; bibliotecas carregadas fora do padrão.  
- **Tráfego leve e periódico** (beaconing) para domínios **recém-registrados**.  
- **Extensões** novas com permissão “Ler e alterar dados de **todos** os sites”.  
- **Entradas de persistência** (Run/RunOnce, tarefas, *LaunchAgents/Daemons*).  
- **Conexões USB** incomuns (novo HID) ou adaptadores inline.

---

## Mitigação & Resposta
- **MFA** (chaves FIDO/U2F) e **cofres de senha** → reduzem impacto de credenciais capturadas.  
- **Navegadores isolados**/perfis separados; **allowlisting** de extensões; **CSP/SRI** para scripts.  
- **EDR/XDR** com políticas anti-injeção, bloqueio de *hooks* suspeitos e detecção de beaconing.  
- **Inspeção física** de teclados/cabos; inventário de dispositivos USB.  
- **Resposta**: isolar host, **invalidar sessões** (SSO, e-mail, bancos), **rotacionar credenciais**, remover extensões/entradas de persistência e revisar logs de acesso.

---

## Demos 100% Seguras para Sala (Sem Malware)

> **Objetivo:** demonstrar o **conceito** (observação de teclas/formulários) **sem capturar conteúdo real**, **sem rede** e **sem persistência**.

### 1) “Keylogger” **anonimizado** (apenas no `<textarea>`)
*Mostra categorias de teclas (L=letra, N=número, ␣, ↵, ⌫, •) — **não** registra caracteres.*

Salve como `keylogger_demo_anon.html`:
```html
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<title>[DEMO] Keylogger ANONIMIZADO (seguro)</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root{--bg:#0c111b;--fg:#e7ebf3;--mut:#9fb1d1;--card:#141a2b;--bord:#26324a}
  body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;display:grid;place-items:center;min-height:100dvh}
  .card{background:var(--card);border:1px solid var(--bord);border-radius:16px;padding:24px;max-width:820px;width:clamp(320px,90vw,820px)}
  textarea{width:100%;min-height:120px;border-radius:12px;border:1px solid var(--bord);background:#0f1524;color:var(--fg);padding:12px}
  .row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
  button{border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer}
  .start{background:#4f7cff;color:#fff}.stop{background:#ff5d5d;color:#fff}
  .box{border:1px solid var(--bord);border-radius:12px;padding:12px;background:#10172b}
</style>
</head>
<body>
  <div class="card">
    <h1>DEMO segura de “keylogger” (anonimizado)</h1>
    <p class="mut">Captura <em>apenas</em> dentro do campo e **não** registra texto real nem envia dados.</p>

    <label for="pad">Área de teste:</label>
    <textarea id="pad" placeholder="Digite aqui..." disabled></textarea>

    <div style="margin:8px 0">
      <input type="checkbox" id="ok"><label for="ok"> Autorizo a captura <strong>anonimizada</strong> <em>somente</em> neste campo.</label>
    </div>

    <div class="row">
      <button id="start" class="start" disabled>Iniciar</button>
      <button id="stop" class="stop" disabled>Parar</button>
    </div>

    <div class="box">
      <strong>Últimas teclas (anonimizadas)</strong>
      <div id="stream" style="min-height:24px;margin-top:6px;word-wrap:break-word"></div>
      <div id="stats" style="color:var(--mut);margin-top:8px">Total: 0 • L:0 • N:0 • ␣:0 • ↵:0 • ⌫:0 • •:0</div>
    </div>
  </div>

<script>
const pad = document.getElementById('pad'), ok = document.getElementById('ok');
const startBtn = document.getElementById('start'), stopBtn = document.getElementById('stop');
const stream = document.getElementById('stream'), stats = document.getElementById('stats');

let enabled=false, counters={T:0,L:0,N:0,SP:0,EN:0,BK:0,O:0};
function cat(k){
  if(k===' ') return '␣';
  if(k==='Enter') return '↵';
  if(k==='Backspace') return '⌫';
  if(/^[a-zA-Z]$/.test(k)) return 'L';
  if(/^[0-9]$/.test(k)) return 'N';
  return '•';
}
function onKeydown(e){
  if(!enabled || e.target!==pad) return;      // restrito ao textarea
  const c = cat(e.key); counters.T++;
  ({'L':'L','N':'N','␣':'SP','↵':'EN','⌫':'BK','•':'O'})[c] && counters[{'L':'L','N':'N','␣':'SP','↵':'EN','⌫':'BK','•':'O'}[c]]++;
  stream.textContent = (stream.textContent + c).slice(-80);
  stats.textContent = `Total: ${counters.T} • L:${counters.L} • N:${counters.N} • ␣:${counters.SP} • ↵:${counters.EN} • ⌫:${counters.BK} • •:${counters.O}`;
}
function start(){
  if(!ok.checked){ alert('Marque o consentimento.'); return; }
  enabled=true; pad.disabled=false; pad.focus();
  startBtn.disabled=true; stopBtn.disabled=false;
  window.addEventListener('keydown', onKeydown, {capture:true});
}
function stop(){
  enabled=false; startBtn.disabled=false; stopBtn.disabled=true;
  window.removeEventListener('keydown', onKeydown, {capture:true});
}
ok.addEventListener('change', ()=> startBtn.disabled=!ok.checked);
startBtn.addEventListener('click', start);
stopBtn.addEventListener('click', stop);
</script>
</body>
</html>
```

Mensagem didática: scripts podem observar eventos do DOM; por isso é vital controlar extensões e políticas de conteúdo (CSP/SRI).

---

### 2) Interceptação de formulário sem conteúdo (comprimento/tempo)
Demonstra que um script poderia “ver” antes do envio; aqui só mostra comprimento/tempo, sem texto nem rede.

Salve como `form_intercept_demo.html`:
```html
<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"/><title>[DEMO] Interceptação segura</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  body{font-family:system-ui;background:#0b1220;color:#e7eaf3;display:grid;place-items:center;min-height:100vh;margin:0}
  .card{background:#141b2d;border:1px solid #26324a;border-radius:16px;padding:24px;max-width:560px;width:clamp(320px,90vw,560px)}
  input{width:100%;padding:10px 12px;border:1px solid #2f3d5a;border-radius:10px;background:#0f1626;color:#e7eaf3}
  label{display:block;margin:12px 0 6px}
  button{margin-top:14px;width:100%;padding:10px 12px;border:0;border-radius:10px;background:#4f7cff;color:#fff;font-weight:700;cursor:pointer}
  .box{border:1px solid #2f3d5a;border-radius:10px;padding:10px;margin-top:10px;background:#10172b}
</style>
</head>
<body>
  <div class="card">
    <h1>DEMO — Formulário (sem capturar texto)</h1>
    <form id="f" autocomplete="off">
      <label for="u">Usuário</label><input id="u" placeholder="ex.: joao" required />
      <label for="p">Senha</label><input id="p" type="password" placeholder="••••••••" required />
      <button type="submit">Entrar</button>
    </form>
    <div id="log" class="box" aria-live="polite"></div>
  </div>
<script>
const f=document.getElementById('f'), u=document.getElementById('u'), p=document.getElementById('p'), log=document.getElementById('log');
let t0u=null,t0p=null;
function msg(s){log.innerHTML+=s+"<br/>";}
u.addEventListener('input',()=>{ if(!t0u) t0u=performance.now(); msg(`Usuário: comprimento=${u.value.length}`);});
p.addEventListener('input',()=>{ if(!t0p) t0p=performance.now(); msg(`Senha: comprimento=${p.value.length} (sem conteúdo)`);});
f.addEventListener('submit',e=>{
  e.preventDefault();
  alert(`DEMO educativa:\n- Nenhum texto capturado.\n- Tempos aproximados: usuário=${t0u? (performance.now()-t0u).toFixed(0)+'ms':'–'}; senha=${t0p? (performance.now()-t0p).toFixed(0)+'ms':'–'}.\nBoas práticas: MFA, CSP, revisão de extensões.`);
  log.innerHTML=""; f.reset(); t0u=t0p=null;
});
</script>
</body>
</html>
```

---

### 3) Checklist rápido de inspeção física (hardware)
- Verifique entre o conector USB e o PC se existe um **adaptador inline** estranho.  
- Confirme **modelo/part number** do teclado com o inventário.  
- Em ambientes corporativos, **proíba periféricos** não inventariados e use **portas USB bloqueadas** por política onde fizer sentido.

---

## Dicas de condução (defensivo)
- Explique **limites dos demos** (sem conteúdo real, sem rede, local).  
- Reforce que **MFA** e **tokens de hardware** neutralizam loggers que só pegam senha.  
- Mostre **políticas de extensões** e **segmentação de perfis** (ex.: um perfil “banco/governo”).  
- Oriente **rotação de senhas** e **invalidação de sessões** ao menor sinal de IoC.

-----

# 🚪 Backdoors — Visão Didática

## O que é
**Backdoors** são acessos **ocultos** criados por invasores (ou, raramente, deixados por desenvolvedores) para **retornar ao ambiente** sem passar pelos controles normais. Podem aparecer como **contas furtivas**, **web shells**, **tarefas/serviços persistentes**, **chaves SSH** não autorizadas ou **modificações em apps/depêndencias** (supply chain).

---

## Como funciona (alto nível)
- **Criação do acesso**: após um comprometimento, o invasor adiciona **usuários ocultos**, **chaves SSH**, **tarefas** ou **web shells**.
- **Persistência & evasão**: nomeia artefatos como “atualização/telemetria”, espalha em locais pouco auditados e tenta burlar logs.
- **Uso sob demanda**: o atacante volta quando quer, usando o canal “secreto” (HTTP(S), SSH, RDP, etc.).
- **Encadeamento**: muitas vezes acompanha **Trojan/Rootkit** ou surge via **supply chain** (pacote dependência/instalador adulterado).

---

## Variantes (alto nível)
- **Usuários/Grupos furtivos** (IAM fraco, senhas padrão, permissões amplas).  
- **Web shell** (arquivo em diretório *web* que aceita comandos) — foco de **WAF** e integridade.  
- **SSH backdoor** (chaves não autorizadas em `authorized_keys`).  
- **Backdoor em binário/dependência** (supply chain, typosquatting).  
- **Serviços/Tarefas** de persistência com nomes genéricos (ex.: “UpdateSvc”).

---

## Vetores comuns
- **Falhas de configuração** (admin padrão, portas expostas, permissões frouxas).  
- **Pós-exploração** (após phishing/exploit, deixam um “retorno”).  
- **Supply chain** (instalador/pacote malicioso, dependência trocada).  

---

## IoCs (Indicadores de Comprometimento)
- **Contas novas/elevadas** inesperadas; alterações em grupos privilegiados.  
- **Chaves SSH** **desconhecidas** em `authorized_keys`.  
- **Arquivos estranhos** no *webroot* (ex.: `.php/.aspx` com padrões de execução).  
- **Tarefas/serviços** recém-criados com nomes genéricos; **beaconing** discreto.  
- **Integridade alterada** (hashes diferentes em binários/scripts críticos).

---

## Mitigação & Resposta
- **Auditoria contínua** (IAM, chaves, serviços, *webroot*, integridade de arquivos).  
- **Rotação de credenciais/segredos** e **MFA**.  
- **WAF** e regras específicas contra **web shells**; bloquear *upload exec*.  
- **Monitoramento de integridade** (baseline de hashes) e telemetria (EDR/XDR).  
- **Supply chain**: verificação de **assinaturas/hashes**, **SBOM**, repositórios confiáveis, *allowlisting*.  
- **Resposta**: **isolar host**, remover backdoors, **corrigir falha raiz**, reconstituir a partir de **mídia confiável**.

---

## Demos 100% Seguras para Sala (Sem Malware)

> Objetivo: treinar **detecção e auditoria** de backdoors usando **comandos apenas de leitura** e **simulações locais**.  
> ⚠️ **Não** criar web shells reais, **não** alterar produção. Faça em laboratório.

### 1) Auditoria de **contas e grupos** (somente leitura)

**Windows (PowerShell):**
```powershell
# Contas locais
Get-LocalUser | Select-Object Name,Enabled,LastLogon | Sort-Object Name

# Membros de Administrators (atenção a entradas inesperadas)
Get-LocalGroupMember -Group "Administrators" | Select-Object Name,PrincipalSource,ObjectClass
```

**Linux:**
```bash
# Usuários "humanos" (UID >= 1000 pode variar por distro)
awk -F: '$3>=1000 {printf "%-20s home=%s shell=%s\n",$1,$6,$7}' /etc/passwd | sort

# Grupos sudo/admin (ajuste para sua distro)
getent group sudo || getent group wheel
```

**macOS:**
```bash
dscl . list /Users | sort | head
dscl . read /Groups/admin GroupMembership
```

Discussão: marque novas contas sem justificativa, admin indevido e lastLogon suspeito.

---

### 2) Auditoria de chaves SSH autorizadas (somente leitura)
**Linux/macOS (como root ou com permissão):**
```bash
for d in /home/* /Users/*; do
  [ -d "$d/.ssh" ] || continue
  echo ">>> $d"
  ls -l "$d/.ssh"
  [ -f "$d/.ssh/authorized_keys" ] && nl -ba "$d/.ssh/authorized_keys" | sed -e 's/\(.\{80\}\).*/\1.../'
done
```

O que observar: chaves recentes sem mudança planejada, comentários estranhos, hosts não reconhecidos.

---

### 3) Varredura segura de webroot (padrões suspeitos)
Simulação: crie uma pasta de laboratório e arquivos fictícios (NUNCA em servidor real). O script só lê e aponta strings suspeitas.

Salve como `scan_webroot_sim.py`:
```python
# DEMO segura: procura *padrões* comuns de web shell (apenas leitura)
import os, re, sys
path = sys.argv[1] if len(sys.argv)>1 else "LAB_WEBROOT"
pats = [
  r"eval\s*\(", r"assert\s*\(", r"base64_decode\s*\(", r"shell_exec\s*\(",
  r"system\s*\(", r"passthru\s*\(", r"popen\s*\(", r"proc_open\s*\("
]
rx = [re.compile(p, re.I) for p in pats]
hits = 0
for root, _, files in os.walk(path):
  for f in files:
    if f.lower().endswith((".php",".asp",".aspx",".jsp",".js",".txt",".html")):
      try:
        with open(os.path.join(root,f), errors="ignore") as h:
          s = h.read()
      except Exception: 
        continue
      bad = [p.pattern for p in rx if p.search(s)]
      if bad:
        hits += 1
        print(f"[suspeito] {os.path.join(root,f)}  padrões={bad}")
print(f"\nResumo: {hits} arquivo(s) com padrões suspeitos (simulação).")
```

**Uso:**
```bash
mkdir -p LAB_WEBROOT
printf '<?php echo "olá"; ?>' > LAB_WEBROOT/index.php
printf '/* simulação: system($_GET["cmd"]); */' > LAB_WEBROOT/talvez_suspeito.txt
python3 scan_webroot_sim.py LAB_WEBROOT
```

Mensagem didática: em produção, use WAF, varreduras CI/CD e monitor de integridade para pegar mudanças/proxies de execução.

---

### 4) Inventário de tarefas/serviços (somente leitura)
**Windows (PowerShell):**
```powershell
# Tarefas agendadas (busque nomes genéricos como "update", "telemetry", "helper")
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Sort-Object TaskPath,TaskName

# Serviços em execução
Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object DisplayName | Select-Object DisplayName,Name
```

**Linux:**
```bash
# Cron do usuário e do sistema
crontab -l 2>/dev/null || echo "sem crontab do usuário"
ls -al /etc/cron.* /etc/cron.d 2>/dev/null

# Serviços/timers
systemctl list-timers --all
systemctl list-units --type=service --state=running
```

**macOS:**
```bash
# LaunchAgents/Daemons
ls -al ~/Library/LaunchAgents
ls -al /Library/LaunchAgents
ls -al /Library/LaunchDaemons
```

O que observar: itens recentes sem mudança planejada, script em pasta temporária, nomes genéricos.

---

### 5) (Opcional) Baseline de integridade de arquivos
Gere e guarde hashes de diretórios críticos (webroot, scripts, binários).  

Compare periodicamente (mudanças inesperadas ⇒ investigar).

**Windows:**
```powershell
Get-FileHash -Algorithm SHA256 -Path C:\inetpub\wwwroot -Recurse
```

**Linux:**
```bash
find /var/www -type f -print0 | xargs -0 sha256sum > baseline.sha256
```

Em produção, prefira ferramentas dedicadas (AIDE, Wazuh, Tripwire) e integração com CI/CD.

---

## Dicas de condução (defensivo)
- Explique que **backdoor ≠ zero-day**: é o atalho colocado para retorno.  
- Reforce políticas de mudança (cada conta/serviço/chave deve ter justificativa e ticket).  
- Mostre playbook de resposta: isolar, coletar artefatos, remover backdoor, corrigir causa raiz, restaurar de fonte confiável e rotacionar segredos.  
- **Supply chain**: peça para a turma verificar assinatura e hash de instaladores; discutir SBOM e pinning de dependências.

---

# 🔹 Ransomware — Visão Didática

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

## 🧪 Demos 100% Seguras para Sala (Sem Malware)

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

## 🗺️ Roteiro sugerido (20–25 min)
- Definição + cadeia (5 min).  
- Locker didático (3–5 min).  
- Cripto em memória (5–7 min) — conceitos de chave/sal/nonce.  
- Backup & restore (5 min).  
- Detecção com log sintético (3–5 min) → discussão de IoCs/playbook.

---

# 🔹 Outros Tipos de Ameaças — Visão Didática

---

## 1) 🕸️ Botnets

### O que são
Redes de dispositivos **infectados e controlados remotamente** (bots/zumbis) por um operador (*botmaster*). Servem para **DDoS**, envio de **spam**, **distribuição de malware** e **mineração**.

### Como funciona (alto nível)
- **Infecção** inicial (phishing, serviço exposto, IoT com senha padrão).
- **Registro** no C2 (Command & Control) para receber ordens.
- **Campanhas** coordenadas (ex.: DDoS, spam, “baixe este payload”).
- **Rotação** de infraestrutura (domínios/endereços trocados para evasão).

### IoCs
- Muitos hosts fazendo **conexões periódicas (beaconing)** a domínios **recém-registrados**.
- **Tráfego volumétrico** para um destino único (padrão de DDoS).
- **Processos idênticos** abrindo conexões de saída em massa.
- **Dispositivos IoT** com tráfego anômalo fora do perfil.

### Mitigação & Resposta
- **Atualizar IoT**, trocar **senhas padrão**, desabilitar serviços desnecessários.
- **Segmentar a rede** (IoT isolado), **deny-by-default** para saídas sensíveis.
- **EDR/IDS/IPS** com detecção de beaconing; **DNS sinkhole**/bloqueio de domínios novos.
- **Contenção rápida** (isolar host), **rotacionar credenciais/tokens** e limpar persistências.

### Demos 100% seguras (Sem Malware)

**A) “Mini-botnet” offline (impressões, sem rede)**  
Salve como `botnet_sim.py`:
```python
# DEMO segura: simula 5 "bots" reportando-se a um C2 fictício (sem rede).
import time, random, uuid, datetime
C2 = "c2.simulado.local"
bots = [str(uuid.uuid4())[:8] for _ in range(5)]
print(f"[start] C2={C2} bots={bots}")

for tick in range(6):
    ts = datetime.datetime.now().isoformat(timespec="seconds")
    for b in bots:
        print(f"[{ts}] bot={b} -> C2={C2} status=ok (simulado)")
    if tick == 3:
        cmd = "MOSTRAR_BANNER"  # "ordem" didática
        print(f"[{ts}] C2 broadcast: {cmd}")
        for b in bots:
            print(f"    bot={b} ação={cmd} resultado=feito")
    time.sleep(random.uniform(0.6, 1.0))
print("[done] Fim da simulação.")
```

Como narrar: padrão de beaconing e execução de “comando” centralizado — sem tráfego real.

**B) Log sintético de DDoS (para caça de IoC)**
```
2025-09-03T14:10:01 SRC=10.0.10.21 DST=203.0.113.50 DPT=443 BYTES=512
2025-09-03T14:10:01 SRC=10.0.10.22 DST=203.0.113.50 DPT=443 BYTES=520
2025-09-03T14:10:01 SRC=10.0.10.23 DST=203.0.113.50 DPT=443 BYTES=515
...
```
Exercício: alunos contam fontes distintas → mesmo destino/porta em janelas curtas ⇒ padrão de ataque volumétrico.

---

## 2) 😱 Scareware

### O que é
Software/alerta enganoso que assusta o usuário (“seu PC está infectado!”) para forçar compra/instalação de algo inútil.

### Como funciona
- Pop-ups alarmistas, telões com contagem regressiva, simulação de scan.
- Pressão psicológica para clicar/pagar.
- Pode tentar instalar PUP/Adware se o usuário “aceitar”.

### IoCs
- Pop-ups insistentes fora do site acessado.
- Ofertas “milagrosas” com gramática ruim URGÊNCIA/AMEAÇA.
- Redirecionamentos para pagamentos.

### Mitigação & Resposta
- Antivírus legítimo, navegador atualizado e bloqueio de pop-ups.
- Educação: não clicar, fechar a aba/janela, limpar extensões.
- EDR para bloquear instaladores suspeitos.

### Demo segura (HTML inofensivo)
Salve como `scareware_demo.html`:
```html
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>[DEMO] Scareware</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{margin:0;background:#0f0f10;color:#e9ecef;font-family:system-ui;display:grid;place-items:center;min-height:100vh}
.panel{max-width:560px;background:#1e2233;border:1px solid #2f3650;padding:28px;border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.5)}
.warn{color:#ff6b6b;font-weight:700}.muted{color:#aeb6c8}.btn{margin-top:16px;display:inline-block;background:#ff4757;color:#fff;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer}</style>
</head>
<body>
  <div class="panel" role="alertdialog">
    <h1 class="warn">⚠️ SEU COMPUTADOR ESTÁ INFECTADO!</h1>
    <p class="muted">Clique para “remover todos os vírus imediatamente”.</p>
    <div class="btn" id="fix">Remover agora</div>
    <p id="edu" class="muted" style="margin-top:12px;display:none"></p>
  </div>
<script>
  fix.onclick=()=>{edu.style.display='block';
    edu.textContent="DEMO: isto é scareware. Feche a aba, use antivírus confiável e não pague por 'limpezas' inesperadas.";}
</script>
</body></html>
```

---

## 3) ⛏️ Cryptojacking

### O que é
Uso indevido de CPU/GPU da vítima para minerar criptomoedas (ganho para o atacante, custo e desgaste para a vítima).

### Como funciona
- Script em site ou malware local roda “hashes” continuamente.
- Consumo elevado de CPU/GPU, aquecimento e ruído.
- Às vezes, só quando o navegador está em foco (para disfarçar).

### IoCs
- CPU/GPU alta sem motivo; fans no máximo.
- Processo de navegador consumindo muito tempo.
- Scripts de terceiros carregados de domínios estranhos.

### Mitigação & Resposta
- Bloqueadores de mineração no navegador; política de scripts de terceiros (CSP/SRI).
- Monitoramento de performance e alerts por uso anômalo.
- EDR para detectar mineradores e persistências.

### Demo segura (HTML com botão Iniciar/Parar)
Salve como `cryptojacking_demo.html`:
```html
<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>[DEMO] Cryptojacking (simulado)</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui;background:#0c111b;color:#e7ebf3;display:grid;place-items:center;min-height:100vh}
.card{background:#141a2b;border:1px solid #26324a;border-radius:16px;padding:28px;max-width:540px}
button{border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer}
.start{background:#4f7cff;color:#fff}.stop{background:#ff5d5d;color:#fff}
progress{width:100%}.muted{color:#9fb1d1}</style></head>
<body>
<div class="card">
  <h1>Simulação de uso excessivo de CPU</h1>
  <p class="muted">Demonstra como scripts podem consumir recursos (sem minerar).</p>
  <div style="display:flex;gap:10px;margin:12px 0">
    <button class="start" id="start">Iniciar</button>
    <button class="stop" id="stop" disabled>Parar</button>
  </div>
  <p>Operações/seg (simulado): <strong id="ops">0</strong></p>
  <progress id="load" max="100" value="0"></progress>
</div>
<script>
let run=false, rid=null;
function heavy(n){let x=0;for(let i=0;i<n;i++){x=(x*1664525+1013904223)>>>0;}return x;}
function loop(){
  if(!run) return;
  const t=performance.now(); let ops=0;
  while(performance.now()-t<200){heavy(5000);ops++;}
  opsEl.textContent=String(ops); load.value=Math.min(100,20+ops);
  rid=requestAnimationFrame(loop);
}
const start=document.getElementById('start'), stop=document.getElementById('stop'), opsEl=document.getElementById('ops'), load=document.getElementById('load');
start.onclick=()=>{run=true;start.disabled=true;stop.disabled=false;loop();};
stop.onclick=()=>{run=false;cancelAnimationFrame(rid);start.disabled=false;stop.disabled=true;opsEl.textContent="0";load.value=0;};
</script>
</body></html>
```

---

## 4) 🧪 Fileless Malware

### O que é
Ataques que não gravam arquivos no disco: operam apenas na memória, abusando de ferramentas legítimas (living off the land) como PowerShell, WMI, rundll32, etc.

### Como funciona
- Script embutido/baixado na memória executa via ferramentas já presentes.
- Persistência por tarefas/agendadores/registro, sem binário novo evidente.
- Evasão: menos artefatos no disco, dificulta antivírus baseados em assinatura.

### IoCs
- Linha de comando suspeita: powershell -enc [BASE64...], wscript //e:jscript, rundll32 javascript:....
- Processos filhos atípicos (Office → PowerShell), AMSI desabilitado.
- Criação de tarefas logo após execução de script.

### Mitigação & Resposta
- EDR/XDR com foco em comportamento (criação de processos, cmdline).
- Bloqueio de macros por padrão; AMSI ativo; Constrained Language Mode.
- Privilégios mínimos, AppLocker/WDAC, PowerShell Logging e Script Block Logging.
- Resposta: isolar host, coletar eventos/detonadores, remover persistências e revisar credenciais.

### Demos 100% seguras (Sem executar nada perigoso)

**A) Detector didático de cmdlines suspeitas (offline)**  
Salve como `fileless_detector_demo.py`:
```python
# DEMO segura: marca exemplos de linhas de comando "sinais" de fileless (não executa nada)
samples = [
  r'powershell -w hidden -enc [BASE64_PAYLOAD]',
  r'wscript.exe //e:jscript script.js',
  r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();',
  r'regsvr32 /s /n /u /i:https://exemplo.test scrobj.dll',
  r'wmic process call create "powershell -nop -c [PAYLOAD]"',
  r'office.exe spawn -> powershell.exe -nop -w hidden'
]
rules = ['powershell','-enc','wscript','rundll32','regsvr32','wmic','office','powershell.exe']

print("Sinais (conceituais) em linhas de comando:\n")
for s in samples:
  hits = [r for r in rules if r.lower() in s.lower()]
  flag = "SUSPEITO" if hits else "OK"
  print(f"[{flag}] {s}\n   ↳ regras: {hits}")
print("\nObs.: Em EDR real, combine processo pai/filho, cmdline completa e horário.")
```

**B) “Duas visões” (scripts em memória vs. em disco) – discussão guiada**  
Mostre que um script pode existir só na memória (ex.: copiado/colado no console) — não faça execução de payload real.  
Discuta como logging do PowerShell/AMSI e EDR ajudam a ver o conteúdo mesmo sem arquivo no disco.

---

# 🔹 Tipos de Ataques em Segurança — Visão Didática

> Objetivo: explicar **como identificar e se defender**, com **demos 100% seguras** (sem exploração, sem rede e sem persistência).

---

## 1) 🎣 Phishing
**O que é:** e-mails/mensagens falsas simulando instituições.  
**Objetivo:** roubo de credenciais/dados.

**IoCs**
- Domínios parecidos (ex.: `pág-bank.com` vs `pagbank.com`), erros de gramática/urgência.
- Links encurtados/estranhos; anexos inesperados (ZIP, DOC com macros).

**Mitigação**
- **Conscientização**, **MFA**, filtros anti-phishing, **DMARC/DKIM/SPF**.
- Verificar **URL real** antes de clicar; nunca inserir senha por links recebidos.

**Demo segura — “texto do link” vs URL real**  
Salve como `phishing_link_demo.html`:
```html
<!doctype html><meta charset="utf-8">
<title>[DEMO] Phishing: texto vs URL</title>
<p>Qual é o link verdadeiro? (não navega)</p>
<ul>
  <li><a href="https://contasegura.exemplo" onclick="event.preventDefault();alert(this.href);">Banco do Brasil</a></li>
  <li><a href="https://bb.com.br.seguranca-login.exemplo" onclick="event.preventDefault();alert(this.href);">Banco do Brasil</a></li>
</ul>
<p>Dica: passe o mouse/pressione e segure no link para ver a URL real.</p>
```

---

## 2) 🎯 Spear Phishing
**O que é:** phishing direcionado (ex.: RH/Finanças).  
**Mitigação:** validação fora do canal (ligação, ticket), política de dupla checagem para dados sensíveis.

**Exercício rápido (sem código)**  
Monte um checklist: remetente corporativo? ticket vinculado? link aponta ao domínio oficial? confirmação por telefone interno?

---

## 3) 🐋 Whaling
**O que é:** ataques a executivos/C-level (ex.: CEO fraud).  
**Mitigação:** workflow de aprovação em transferências, alerta de “urgência” fora de horário, contas VIP com MFA forte e treinamento específico.

**Simulação didática**  
Peça à turma para propor um fluxo “pedido urgente do CEO” → duas validações humanas + registro em sistema.

---

## 4) 🧠 Engenharia Social
**O que é:** manipulação psicológica (ex.: “suporte” pedindo senha).  
**Mitigação:** política “nunca compartilhe senhas”, palavra-secreta para validação por telefone, scripts de atendimento.

**Roteiro de resposta (role-play)**  
Pergunte nome/ramal/ticket, devolva ligação via número oficial, registre tentativa.

---

## 5) 🔐 Ataques de Senha
**Tipos:** Brute Force, Dictionary, Credential Stuffing (reuso de senhas vazadas).  
**Mitigação:** MFA, senhas fortes/gerenciador, rate-limit e bloqueio progressivo, monitoramento de vazamentos.

**Demo segura — Espaço de senhas (sem quebrar nada)**  
Salve como `password_space_demo.py`:
```python
# Calcula o espaço de busca e tempo estimado (puramente didático)
from math import pow
alfabetos = {"num":10,"min":26,"min+num":36,"min+mai+num":62}
tentativas_por_seg = 1_000  # mude para mostrar impacto de rate-limit
for nome, A in alfabetos.items():
    for L in (4,6,8,10,12):
        N = int(pow(A,L))
        segundos = N / tentativas_por_seg
        print(f"{nome:12} L={L:2} → {N:.2e} combinações (~{segundos/86400:.2f} dias @{tentativas_por_seg}/s)")
```

Explique: MFA derruba a utilidade do brute force mesmo com senhas fracas.

---

## 6) 🌐 Ataques de Rede (Sniffing, Spoofing, MITM)
**Como funcionam:** interceptam/forjam tráfego; em MITM, um atacante fica “entre” cliente e servidor.  
**Mitigação:** HTTPS/TLS em tudo, HSTS, VPN em redes não confiáveis, IDS/IPS, segmentação.

**Exercício seguro (conceitual)**  
Abra um site com cadeado e mostre detalhes do certificado (cadeia/emitente).  
Discuta “o que observar” quando aparece alerta de certificado (nunca ignore).

---

## 7) 🌊 DoS/DDoS
**O que é:** sobrecarga para indisponibilizar.  
**Mitigação:** mitigação em nuvem, rate-limit, caches/CDN, auto-scaling, WAF e filtros upstream.

**Demo segura — Log sintético de pico**
```
2025-09-03T10:00:00 RPS=1800 SRCs=120 DST=api.exemplo
2025-09-03T10:00:05 RPS=5200 SRCs=900  DST=api.exemplo  <-- anômalo
2025-09-03T10:00:10 RPS=9800 SRCs=2000 DST=api.exemplo  <-- mitigação deveria acionar
```
**Atividade:** decidir limites e gatilhos de mitigação.

---

## 8) 🧩 Exploração de Vulnerabilidades
**Exemplo histórico:** SMBv1 no WannaCry.  
**Mitigação:** patching contínuo, gestão de vulnerabilidades (scan + priorização), pentests e segurança por design.

**Checklist prático**  
- Inventário → priorize expostos à internet e CVE explorada ativamente.  
- Política de janela de manutenção e rollback.

---

## 9) 💉 SQL Injection (SQLi) e ✳️ XSS
**SQLi:** manipula consultas ao banco.  
**XSS:** injeta script no navegador de vítimas.

**Mitigação:** validação/escape de entrada, ORM/queries parametrizadas, CSP, WAF.

**Demo segura — Parametrização (Python + sqlite3)**
```python
# NÃO executa nada perigoso; mostra a forma correta (parametrizada)
import sqlite3
db = sqlite3.connect(":memory:")
db.execute("create table users (id int, name text)")
db.execute("insert into users values (?,?)", (1,"alice"))
user_input = "alice' OR '1'='1"  # exemplo clássico (não será injetado)
rows = db.execute("select * from users where name = ?", (user_input,)).fetchall()
print("Resultado seguro (parametrizado):", rows)  # retorna vazio
```

**Demo segura — Escapar conteúdo no front-end**  
Salve como `xss_safe_demo.html`:
```html
<!doctype html><meta charset="utf-8">
<p>Entrada do usuário:</p>
<input id="in" placeholder='Ex.: <b>oi</b>'>
<pre id="out"></pre>
<script>
  const esc = s => s.replace(/[&<>"']/g, m=>({"&":"&amp;","<":"&lt;","&gt;":"&gt;","\"":"&quot;","'":"&#39;"}[m]));
  in.oninput = () => out.textContent = esc(in.value); // sempre textContent/escape
</script>
```

---

## 10) 🕳️ Zero-Day
**O que é:** falha desconhecida/sem correção disponível.  
**Mitigação:** monitoramento comportamental (EDR/XDR), segmentação de ativos críticos, princípio do menor privilégio, bug bounty e defesa em profundidade.

**Exercício (tabletop, sem código)**  
“Se amanhã surgir um zero-day crítico no seu gateway SSO, qual o plano?”  
- Limitar exposição? Regras compensatórias/WAF?  
- MFA reforçado?  
- Comunicado interno e telemetria ampliada?

---

# 🔹 Boas Práticas de Defesa — Guia Didático

> Objetivo: consolidar medidas **preventivas e reativas** com exemplos e **laboratórios 100% seguros** para treinamento.

---

## 1) 🔄 Atualizações e Patches Regulares
**Por que:** fecham **falhas conhecidas** exploradas por ataques amplos.  
**Como aplicar (essencial):**
- Habilite **atualização automática** onde possível.
- Mantenha **inventário** de ativos e **priorize** o que está exposto à internet e CVEs **exploradas ativamente**.
- Tenha **janela de manutenção** e plano de **rollback**.
- Use ferramentas de gestão de vulnerabilidades (ex.: scanners) para **medir** e **acompanhar** SLA de correção.

---

## 2) 🛡️ Antivírus/Antimalware + EDR/XDR
**Por que:** AV/AM bloqueiam **famílias conhecidas**; **EDR/XDR** detectam **comportamentos** (script anômalo, beaconing, lateralidade).  
**Como aplicar:**
- Ative **heurística/análise comportamental**.
- Centralize **telemetria** em **SIEM**.
- Bloqueie **macros** por padrão; use **allowlisting** (AppLocker/WDAC) para reduzir superfície.

---

## 3) 💾 Backups Frequentes (Regra 3–2–1)
**Por que:** garante **recuperação** frente a ransomware/falhas.  
**Regra 3-2-1:** **3** cópias, **2** mídias diferentes, **1** offsite/offline (ou imutável).  
**Como aplicar:**
- **Teste restauração** periodicamente (RTO/RPO definidos).
- Isole o repositório de backup de **contas comuns** (reduz criptografia simultânea).

---

## 4) 🔐 Autenticação Multifator (MFA)
**Por que:** reduz drasticamente o impacto do **roubo de senha** (phishing, stuffing).  
**Como aplicar:**
- Priorize **SSO**, **VPN**, **RDP**, e **painéis administrativos**.  
- Prefira **chaves FIDO/U2F** ou apps autenticadores.  
- Eduque sobre **prompts MFA** (evitar aceitação por cansaço).

---

## 5) 👀 Monitoramento Contínuo & Resposta a Incidentes
**Por que:** **detecção precoce** diminui dano.  
**Como aplicar:**
- **SIEM** com regras (ex.: surto de renomeações, domínios recém-registrados, PS encodado).
- **SOC/CSIRT** com **playbooks** (isolar, preservar artefatos, erradicar, recuperar, revisar).
- Exercícios **tabletop** e pós-incidente com **lições aprendidas**.

---

## 6) 🧠 Treinamento de Usuários
**Por que:** pessoas são alvo de **engenharia social**.  
**Como aplicar:**
- Simulações de **phishing** periódicas (com feedback imediato).
- Políticas claras: **não compartilhar senhas**, **validação fora do canal**, dupla checagem financeira.
- Cultura de **reportar** suspeitas (sem punição por “falso positivo”).

---

> **Defesa em Profundidade:** combine **tecnologia, processos e pessoas**. Nenhuma camada é perfeita; juntas, **reduzem muito o risco**.

---

# 🧪 Laboratórios Didáticos (100% Seguros)

> Projetados **sem rede**, **sem persistência** e **sem coletar dados reais** — focados em **conscientização e defesa**.

---

## 1) Phishing (página falsa **educativa**)
**Mostra:** como texto do link difere da **URL real**; sem coletar/enviar credenciais.  
**Salve como `phishing_demo.html` e abra no navegador:**
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>[DEMO DIDÁTICA] Phishing</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;display:grid;place-items:center;min-height:100dvh;background:#0b1220;color:#e7eaf3}
    .card{background:#141b2d;border:1px solid #26324a;border-radius:16px;padding:28px;max-width:360px;width:100%;box-shadow:0 8px 30px rgba(0,0,0,.35)}
    h1{margin:0 0 6px;font-size:1.25rem}
    p.badge{margin:0 0 16px;color:#9fb1d1}
    label{display:block;margin:12px 0 6px}
    input{width:100%;padding:10px 12px;border:1px solid #2f3d5a;border-radius:10px;background:#0f1626;color:#e7eaf3}
    button{margin-top:16px;width:100%;padding:10px 12px;border:0;border-radius:10px;background:#4f7cff;color:#fff;font-weight:600;cursor:pointer}
    .edu{margin-top:18px;font-size:.9rem;color:#9fb1d1}
    .banner{position:fixed;inset:12px auto auto 12px;background:#ffbe0b;color:#1a1a1a;padding:6px 10px;border-radius:8px;font-weight:700}
  </style>
</head>
<body>
  <div class="banner">DEMONSTRAÇÃO DIDÁTICA — NÃO USE CREDENCIAIS REAIS</div>
  <div class="card" role="region" aria-label="Formulário de demonstração">
    <h1>Entre na sua conta</h1>
    <p class="badge">*Exemplo educacional de página falsa*</p>

    <form id="demo-form" autocomplete="off">
      <label for="email">E-mail</label>
      <input id="email" type="email" placeholder="voce@exemplo.com" required />
      <label for="pwd">Senha</label>
      <input id="pwd" type="password" placeholder="••••••••" required />
      <button type="submit">Entrar</button>
    </form>

    <div class="edu" id="edu" hidden></div>
  </div>

  <script>
    document.getElementById('demo-form').addEventListener('submit', (e) => {
      e.preventDefault();
      alert(`⚠️ ESTA É UMA SIMULAÇÃO DE PHISHING.
Nunca insira credenciais em páginas suspeitas.
Verifique o endereço (URL/HTTPS), ortografia e remetente.
Habilite MFA sempre que possível.`);
      const edu = document.getElementById('edu');
      edu.hidden = false;
      edu.textContent = "Dica: passe o mouse sobre o link e confirme a URL real antes de clicar.";
      e.target.reset();
    });
  </script>
</body>
</html>
```

---

## 2) Adware (banners inofensivos, sem persistência)
**Mostra:** pop-ups/overlays como adware faria (só dentro da página).  
**Salve como `adware_demo.html`:**
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>[DEMO DIDÁTICA] Adware</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{--bg:#0e0f13;--fg:#e9ecf1;--muted:#a8b0bf;--accent:#ff4757}
    body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif}
    header{padding:20px;border-bottom:1px solid #232631}
    main{padding:24px;max-width:900px;margin:0 auto}
    button{border:0;border-radius:10px;padding:10px 14px;font-weight:600;cursor:pointer}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .banner{position:fixed;left:12px;bottom:12px;background:#ffeaa7;color:#111;padding:10px 14px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.4)}
    .ad{position:fixed;background:#1b1e2a;border:1px solid #30364a;color:#e9ecf1;border-radius:14px;box-shadow:0 16px 42px rgba(0,0,0,.5);width:280px;padding:14px}
    .ad h3{margin:0 0 6px}
    .muted{color:var(--muted)}
    .close{float:right;background:var(--accent);color:#fff;border-radius:8px;padding:4px 8px}
  </style>
</head>
<body>
  <header>
    <h1>DEMO: Comportamento “Adware” (inofensivo)</h1>
    <p class="muted">Banners irritantes — <strong>apenas nesta página</strong>.</p>
  </header>

  <main>
    <div class="row">
      <button id="spawn">Gerar anúncio</button>
      <button id="spawnMany">Gerar vários</button>
      <button id="clearAll">Remover todos</button>
      <button id="toggleHome">Alterar “página inicial” (falso)</button>
    </div>
    <p style="margin-top:18px;color:var(--muted)">Simulação didática — não altera configurações reais.</p>
  </main>

  <div class="banner" id="banner" hidden>
    “Sua página inicial foi alterada!” — <button id="undo">Desfazer</button>
  </div>

  <script>
    let count = 0;
    function createAd(x=20,y=80){
      const ad = document.createElement('div');
      ad.className = 'ad';
      ad.style.left = (x + Math.random()*40) + 'px';
      ad.style.top  = (y + Math.random()*40) + 'px';
      ad.style.zIndex = 1000 + count++;
      ad.innerHTML = `
        <button class="close" aria-label="Fechar">x</button>
        <h3>Promoção Imperdível!</h3>
        <p class="muted">Clique aqui! Clique aqui! Clique aqui!</p>
      `;
      ad.querySelector('.close').onclick = () => ad.remove();
      ad.onmousedown = (e) => {
        const dx = e.clientX - ad.offsetLeft, dy = e.clientY - ad.offsetTop;
        function move(ev){ad.style.left=(ev.clientX-dx)+'px';ad.style.top=(ev.clientY-dy)+'px';}
        function up(){window.removeEventListener('mousemove',move);window.removeEventListener('mouseup',up);}
        window.addEventListener('mousemove',move);window.addEventListener('mouseup',up);
      };
      document.body.appendChild(ad);
    }
    spawn.onclick = ()=> createAd(40,120);
    spawnMany.onclick = ()=> { for(let i=0;i<4;i++) createAd(60+i*40,140+i*30); };
    clearAll.onclick = ()=> document.querySelectorAll('.ad').forEach(e=>e.remove());
    toggleHome.onclick = ()=> banner.hidden = false;
    undo.onclick = ()=> banner.hidden = true;
  </script>
</body>
</html>
```

---

## 3) Scareware (alerta falso educativo)
**Mostra:** como mensagens de pânico tentam forçar cliques/pagamentos.  
**Salve como `scareware_demo.html`:**
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>[DEMO DIDÁTICA] Scareware</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{margin:0;background:#0f0f10;color:#e9ecef;font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif}
    .full{position:fixed;inset:0;display:grid;place-items:center;background:radial-gradient(ellipse at center,#1d1f2a 0%,#0f0f10 60%)}
    .panel{max-width:560px;background:#1e2233;border:1px solid #2f3650;padding:28px;border-radius:16px;box-shadow:0 16px 48px rgba(0,0,0,.5)}
    h1{margin:0 0 8px}.warn{color:#ff6b6b;font-weight:700}.muted{color:#aeb6c8}
    .btn{margin-top:16px;display:inline-block;background:#ff4757;color:#fff;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer}
  </style>
</head>
<body>
  <div class="full">
    <div class="panel" role="alertdialog" aria-label="Alerta falso">
      <h1 class="warn">⚠️ SEU COMPUTADOR ESTÁ INFECTADO!</h1>
      <p class="muted">Clique para “remover todos os vírus imediatamente”.</p>
      <div class="btn" id="fix">Remover agora</div>
      <p id="edu" class="muted" style="margin-top:18px;display:none"></p>
    </div>
  </div>
  <script>
    fix.onclick = () => {
      edu.style.display = 'block';
      edu.textContent = "DEMO: isto é scareware. Feche a aba, não pague, use antivírus legítimo.";
      alert("Educação: desconfie de URGÊNCIA, erros de gramática e pedidos de pagamento.");
    };
  </script>
</body>
</html>
```

---

## 4) Cryptojacking (uso de CPU simulado)
**Mostra:** script consumindo CPU; botão de parar.  
**Salve como `cryptojacking_demo.html`:**
```html
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>[DEMO DIDÁTICA] Cryptojacking (simulado)</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#0c111b;color:#e7ebf3;display:grid;place-items:center;min-height:100dvh}
    .card{background:#141a2b;border:1px solid #26324a;border-radius:16px;padding:28px;max-width:540px;box-shadow:0 8px 30px rgba(0,0,0,.35)}
    button{border:0;border-radius:10px;padding:10px 14px;font-weight:700;cursor:pointer}
    .start{background:#4f7cff;color:#fff}.stop{background:#ff5d5d;color:#fff}
    .muted{color:#9fb1d1} progress{width:100%}
  </style>
</head>
<body>
  <div class="card">
    <h1>Simulação de uso excessivo de CPU</h1>
    <p class="muted">Demonstra como scripts maliciosos podem consumir recursos.</p>
    <div style="display:flex;gap:10px;margin:12px 0">
      <button class="start" id="start">Iniciar “mineração” (falsa)</button>
      <button class="stop" id="stop" disabled>Parar</button>
    </div>
    <p>Operações por segundo (estimado): <strong id="ops">0</strong></p>
    <progress id="load" max="100" value="0"></progress>
  </div>
  <script>
    let running=false, rafId=null;
    function fakeHash(n){let x=0;for(let i=0;i<n;i++){x=(x*1664525+1013904223)>>>0;}return x;}
    function loop(){
      if(!running) return;
      const start=performance.now(); let ops=0;
      while(performance.now()-start<200){ fakeHash(5000); ops++; }
      opsEl.textContent=String(ops); load.value=Math.min(100,20+ops);
      rafId=requestAnimationFrame(loop);
    }
    const startBtn=start, stopBtn=stop, opsEl=ops, load=load;
    startBtn.onclick=()=>{running=true;startBtn.disabled=true;stopBtn.disabled=false;loop();};
    stopBtn.onclick=()=>{running=false;cancelAnimationFrame(rafId);startBtn.disabled=false;stopBtn.disabled=true;opsEl.textContent="0";load.value=0;};
  </script>
</body>
</html>
```

---

## 5) Pasta “protegida por senha” (OpenSSL) — sem código malicioso
**Mostra:** confidencialidade e reversibilidade com senha, como numa restauração após incidente.
```bash
# 1) Empacotar a pasta em .tar
tar -cvf LAB_SEGURO.tar LAB_SEGURO

# 2) Criptografar (AES-256-CBC + PBKDF2 com iterações altas)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 250000 -in LAB_SEGURO.tar -out LAB_SEGURO.enc

# 3) (Opcional) Verifique que os originais permanecem intactos (é um laboratório)

# 4) Descriptografar depois
openssl enc -d -aes-256-cbc -pbkdf2 -iter 250000 -in LAB_SEGURO.enc -out RECUPERADO.tar

# 5) Extrair conteúdo recuperado
mkdir -p RECUPERADO && tar -xvf RECUPERADO.tar -C RECUPERADO
```

---

## 6) Mini-lab de Criptografia em Memória (Python, AES-GCM)
**Mostra:** PBKDF2 + sal, nonce único e AEAD (confidencialidade+integridade) — sem tocar em disco.
```python
# pip install cryptography
import os, json, base64
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))

def derivar_chave(senha: str, sal: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=sal, iterations=300_000)
    return kdf.derive(senha.encode())

def cifrar_texto(plaintext: str, senha: str) -> str:
    sal = os.urandom(16); chave = derivar_chave(senha, sal); gcm = AESGCM(chave); nonce = os.urandom(12)
    ct = gcm.encrypt(nonce, plaintext.encode(), None)
    return json.dumps({"salt": b64e(sal), "nonce": b64e(nonce), "ct": b64e(ct)}, indent=2, ensure_ascii=False)

def decifrar_texto(pacote_json: str, senha: str) -> str:
    d = json.loads(pacote_json); sal, nonce, ct = b64d(d["salt"]), b64d(d["nonce"]), b64d(d["ct"])
    chave = derivar_chave(senha, sal); return AESGCM(chave).decrypt(nonce, ct, None).decode()

if __name__ == "__main__":
    senha = "SenhaDidatica123!"
    texto = "Conteúdo EXEMPLO.TXT (simulado em memória)."
    print(">>> CIFRANDO..."); pacote = cifrar_texto(texto, senha); print(pacote)
    print("\n>>> DECIFRANDO..."); print(decifrar_texto(pacote, senha))
```

---

## 7) Keylogger anonimizado (somente nesta página, sem rede)
**Mostra:** captura de eventos no DOM sem registrar caracteres reais.  
Salve como `keylogger_demo_anon.html`: *(versão resumida — igual à anterior que você já usa)*

✔️ Relembrar em aula: **MFA**, políticas de extensões e **CSP/SRI** mitigam esse vetor.

---

## 8) Interceptação de Formulário (sem caracteres)
**Mostra:** comprimento e tempos de digitação; nunca o texto.  
Salve como `form_intercept_demo.html`: *(versão resumida — igual à anterior que você já usa)*

---

## ✅ Checklist Rápido para Aula & Operação
- **Patching & Inventário:** métricas de SLA por criticidade; janelas regulares.  
- **EDR/XDR + SIEM:** regras para ransom notes, explosão de I/O, PS encodado, domínios novos.  
- **Backups 3–2–1:** testes de restauração (RTO/RPO).  
- **MFA em tudo crítico:** SSO/VPN/RDP/Admin.  
- **Políticas de navegador:** bloqueio de extensões não aprovadas, CSP/SRI.  
- **Treinamento contínuo:** phishing, engenharia social, reporte rápido.  
- **Playbooks de resposta (tabletop):** isolar, preservar, erradicar, recuperar, revisar.
