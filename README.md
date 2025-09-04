# 🔹 O que é Malware?

**Malware** vem do termo *"Malicious Software"* (software malicioso).  
👉 É qualquer programa, código ou arquivo criado com o objetivo de **danificar sistemas, roubar informações, comprometer a privacidade, extorquir valores ou causar indisponibilidade de serviços**.  

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

👉 **Em resumo:** todo vírus é um malware, mas nem todo malware é um vírus.  
O termo **malware** é o “guarda-chuva” que engloba **vírus, worms, trojans, ransomware, spyware, adware, rootkits, keyloggers, backdoors**, entre outros.  

---

# 🔹 Malware e suas Categorias

## Vírus
- **O que é/como funciona:** precisa de um hospedeiro (arquivo, setor de boot, macro) para se replicar. Variantes: *file infector*, *macro vírus*, *boot sector*, *polimórfico/metamórfico*.  
- **Vetores comuns:** anexos de e-mail com macros, cracks, mídias removíveis com *autorun*.  
- **IoCs:** arquivos alterados, macros inesperadas, chaves de inicialização suspeitas.  
- **Mitigação/Resposta:** desabilitar macros, antivírus com heurística, varredura em *Safe Mode*, backups limpos.  

## Worms
- **O que é/como funciona:** se auto-propaga explorando falhas de rede, sem interação do usuário.  
- **Vetores comuns:** serviços expostos (SMB/RDP/HTTP), IoT desatualizada.  
- **IoCs:** tráfego de rede anormal, conexões suspeitas, processos em massa.  
- **Mitigação/Resposta:** patching rápido, segmentação de rede, firewalls restritivos.  

## Trojan (Cavalo de Troia)
- **O que é/como funciona:** disfarçado de software legítimo, instala payload malicioso (RAT, ladrão de senhas).  
- **Vetores comuns:** phishing, cracks, malvertising.  
- **IoCs:** processos estranhos conectando-se a domínios C2, serviços/tarefas inesperados.  
- **Mitigação/Resposta:** privilégios mínimos, bloqueio de software não assinado, EDR com detecção de beaconing.  

## Spyware
- **O que é/como funciona:** coleta informações sem consentimento (histórico, senhas, localização).  
- **Vetores comuns:** anexos maliciosos, extensões de navegador, bundles de freeware.  
- **IoCs:** extensões suspeitas, tráfego para pastebins, certificados raiz novos.  
- **Mitigação/Resposta:** bloqueio de extensões, uso de cofres de senha, inspeção TLS.  

## Adware
- **O que é/como funciona:** injeta propagandas, altera mecanismos de busca e pode abrir porta para outros malwares.  
- **Vetores comuns:** instaladores “free”, sites de *warez*.  
- **IoCs:** pop-ups fora do comum, redirecionamentos, serviços estranhos.  
- **Mitigação/Resposta:** restauração de navegador, bloqueio de *bundlers*, varredura antimalware.  

## Rootkits
- **O que é/como funciona:** ocultam processos/arquivos, garantindo persistência e evasão.  
- **Vetores comuns:** exploração de kernel, drivers comprometidos, boot adulterado.  
- **IoCs:** divergência em logs, Secure Boot desativado, drivers suspeitos.  
- **Mitigação/Resposta:** Secure Boot, EDR com integridade, reinstalação limpa.  

## Keyloggers
- **O que é/como funciona:** capturam teclas e formulários. Podem ser software ou hardware.  
- **Vetores comuns:** trojans, phishing, dispositivos USB adulterados.  
- **IoCs:** DLLs injetadas, tráfego leve e constante para C2.  
- **Mitigação/Resposta:** MFA, navegadores isolados, inspeção física.  

## Backdoors
- **O que é/como funciona:** criam acessos ocultos para invasores (usuários furtivos, web shells, chaves SSH).  
- **Vetores comuns:** falhas de configuração, pós-exploração, supply chain.  
- **IoCs:** contas novas, chaves SSH desconhecidas, web shells em diretórios *web*.  
- **Mitigação/Resposta:** auditoria contínua, rotação de credenciais, WAF, monitoramento de integridade.  

---

# 🔹 Ransomware

## 📌 Definição
Ransomware é um tipo de malware de extorsão que **sequestra dados** via criptografia e exige **pagamento de resgate** (geralmente em criptomoedas).  

## 📌 Propagação
- Phishing com links/arquivos maliciosos.  
- Documentos com macros.  
- Exploração de vulnerabilidades (RDP/SMB).  
- Downloads infectados.  
- Movimento lateral na rede.  

## 📌 Impactos
- Indisponibilidade de dados.  
- Paralisação de operações.  
- Perdas financeiras e multas.  
- Danos à reputação.  
- Vazamento de dados (*double extortion*).  

## 📌 Tipos
1. **Crypto-Ransomware:** criptografa arquivos (ex.: WannaCry).  
2. **Locker Ransomware:** bloqueia a tela, sem criptografar arquivos.  
3. **Scareware:** assusta com mensagens falsas.  
4. **Doxware/Leakware:** ameaça divulgar dados roubados.  
5. **Ransomware-as-a-Service (RaaS):** modelo de negócio alugado a criminosos.  
6. **Mobile Ransomware:** afeta smartphones, bloqueando PIN ou criptografando arquivos.  

## 📌 Exemplos Famosos
- WannaCry, Petya/NotPetya, Locky, Ryuk.  

---

# 🔹 Outros Tipos de Ameaças

## 1. Botnets
- **O que são:** redes de dispositivos infectados controlados remotamente (zumbis).  
- **Objetivos:** DDoS, spam, distribuição de malware, mineração.  
- **Exemplos:** Mirai, Zeus.  
- **Defesa:** atualização de IoT, troca de senhas padrão, monitoramento de tráfego.  

## 2. Scareware
- **O que é:** simula alertas falsos de vírus para forçar compra de softwares inúteis.  
- **Exemplo:** pop-ups de “seu PC está infectado!”.  
- **Defesa:** antivírus legítimo, não clicar em links suspeitos.  

## 3. Cryptojacking
- **O que é:** usa CPU/GPU da vítima para minerar criptomoedas.  
- **Formas:** malware local ou scripts em sites.  
- **Defesa:** bloqueadores de mineração, monitoramento de performance.  

## 4. Fileless Malware
- **O que é:** atua somente na memória, sem gravar arquivos no disco.  
- **Exemplo:** scripts PowerShell/WMI maliciosos.  
- **Defesa:** EDR, bloqueio de macros, princípio do menor privilégio.  

---

# 🔹 Tipos de Ataques em Segurança

## 1. Phishing
- E-mails/mensagens falsas simulando instituições.  
- **Objetivo:** roubo de credenciais.  
- **Defesa:** conscientização, MFA, filtros.  

## 2. Spear Phishing
- Phishing direcionado a vítimas específicas.  
- **Exemplo:** setor de RH.  
- **Defesa:** checagem fora do canal digital.  

## 3. Whaling
- Focado em executivos e alta gestão.  
- **Exemplo:** fraudes CEO fraud.  
- **Defesa:** dupla checagem em transferências.  

## 4. Engenharia Social
- Manipulação psicológica para obter informações.  
- **Exemplo:** ligação se passando por suporte.  

## 5. Ataques de Senha
- **Brute Force, Dictionary, Credential Stuffing.**  
- **Defesa:** senhas fortes, MFA, limitação de tentativas.  

## 6. Ataques de Rede
- **Sniffing, Spoofing, Man-in-the-Middle.**  
- **Defesa:** criptografia (HTTPS, VPN), IDS/IPS.  

## 7. DoS/DDoS
- Sobrecarga para indisponibilizar serviços.  
- **Exemplo:** Mirai.  
- **Defesa:** mitigação em nuvem, balanceadores.  

## 8. Exploração de Vulnerabilidades
- **Exemplo:** SMBv1 no WannaCry.  
- **Defesa:** patching, pentests.  

## 9. SQL Injection e XSS
- **SQLi:** manipulação de banco de dados.  
- **XSS:** injeção de scripts em sites.  
- **Defesa:** validação de entrada, WAF.  

## 10. Zero-Day
- Exploração de falha ainda desconhecida.  
- **Defesa:** monitoramento comportamental, bug bounty.  

---

# 🔹 Boas Práticas de Defesa

## 1. Atualizações e patches regulares
- **Por que:** fecham falhas conhecidas.  
- **Exemplo:** falha explorada pelo WannaCry.  

## 2. Uso de antivírus e antimalware
- **Por que:** detectam malwares conhecidos.  
- **Complemento:** EDR/XDR para análise em tempo real.  

## 3. Backup frequente dos dados críticos
- **Regra 3-2-1:** 3 cópias, 2 mídias, 1 offsite.  
- **Exemplo:** hospitais recuperados após ransomware.  

## 4. Autenticação multifator (MFA)
- **Protege mesmo com senha vazada.**  
- **Exemplo:** reduzir credential stuffing.  

## 5. Monitoramento contínuo e resposta a incidentes
- **Ferramentas:** SIEM, SOC/CSIRT, playbooks de resposta.  
- **Exemplo:** detectar tráfego anormal para C2.  

## 6. Treinamento de usuários
- **Por que:** humanos são elo fraco.  
- **Exemplo:** simulação de phishing reduz chance de ataques em 70%.  

👉 **Defesa em profundidade:** camadas de segurança combinando **tecnologia, processos e pessoas**.  

-------

1) Phishing (didático e inofensivo)

O que mostra: como uma página falsa poderia enganar alguém — sem coletar dados, sem rede, e com aviso educativo claro.

Salve como phishing_demo.html e abra no navegador.

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
      // NÃO coleta, NÃO envia, só educa:
      const msg = `
⚠️ ESTA É UMA SIMULAÇÃO DE PHISHING.
Nunca insira credenciais em páginas suspeitas.
Verifique o endereço (URL/HTTPS), ortografia e remetente.
Habilite MFA sempre que possível.`;
      alert(msg);
      const edu = document.getElementById('edu');
      edu.hidden = false;
      edu.textContent = "Dica: verifique a URL, cadeado HTTPS e suspeite de urgências/ameaças no texto.";
      (e.target).reset();
    });
  </script>
</body>
</html>

2) Adware (inofensivo — só “irritante”)

O que mostra: pop-ups/banners invasivos dentro da própria página (sem persistência, sem instalar nada).

Salve como adware_demo.html.

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
    <p class="muted">Gera banners irritantes e overlays — <strong>apenas nesta página</strong>.</p>
  </header>

  <main>
    <div class="row">
      <button id="spawn">Gerar anúncio</button>
      <button id="spawnMany">Gerar vários</button>
      <button id="clearAll">Remover todos</button>
      <button id="toggleHome">Alterar “página inicial” (falso)</button>
    </div>
    <p style="margin-top:18px;color:var(--muted)">Isto é apenas uma simulação didática — não altera configurações reais.</p>
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
        const dx = e.clientX - ad.offsetLeft;
        const dy = e.clientY - ad.offsetTop;
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

3) Scareware (mensagem enganosa, mas educativa)

O que mostra: uma “tela de pânico” que tenta obrigar o clique — no nosso caso, leva a uma explicação.

Salve como scareware_demo.html.

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
    h1{margin:0 0 8px}
    .warn{color:#ff6b6b;font-weight:700}
    .muted{color:#aeb6c8}
    .btn{margin-top:16px;display:inline-block;background:#ff4757;color:#fff;padding:10px 14px;border-radius:10px;font-weight:700;cursor:pointer}
  </style>
</head>
<body>
  <div class="full">
    <div class="panel" role="alertdialog" aria-label="Alerta falso">
      <h1 class="warn">⚠️ SEU COMPUTADOR ESTÁ INFECTADO!</h1>
      <p class="muted">Clique no botão para “remover todos os vírus imediatamente”.</p>
      <div class="btn" id="fix">Remover agora</div>
      <p id="edu" class="muted" style="margin-top:18px;display:none"></p>
    </div>
  </div>

  <script>
    document.getElementById('fix').onclick = () => {
      const edu = document.getElementById('edu');
      edu.style.display = 'block';
      edu.textContent =
        "Isto é uma demonstração de scareware. Dicas: desconfie de urgências, " +
        "erros de gramática, pop-ups agressivos e pedidos de pagamento. Feche a aba e use um antivírus legítimo.";
      alert("DEMO: Nunca pague por 'limpezas' que surgem do nada.");
    };
  </script>
</body>
</html>

7) Cryptojacking (simulação leve, com botão de parar)

O que mostra: como um script pode “comer CPU” — sem minerar e com botão de parar.

Salve como cryptojacking_demo.html.

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
    .start{background:#4f7cff;color:#fff}
    .stop{background:#ff5d5d;color:#fff}
    .muted{color:#9fb1d1}
    progress{width:100%}
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
    <p class="muted" style="margin-top:10px">Use o Gerenciador de Tarefas/Monitor de Atividade para observar a CPU.</p>
  </div>

  <script>
    let running = false, rafId = null;
    function fakeHash(n){
      // Alguma carga CPU: operações matemáticas inúteis
      let x = 0;
      for(let i=0;i<n;i++){ x = (x * 1664525 + 1013904223) >>> 0; }
      return x;
    }
    function loop(){
      if(!running) return;
      const start = performance.now();
      let ops = 0;
      while (performance.now() - start < 200) { // ~200ms de trabalho
        fakeHash(5000); ops++;
      }
      document.getElementById('ops').textContent = String(ops);
      document.getElementById('load').value = Math.min(100, 20 + ops);
      rafId = requestAnimationFrame(loop);
    }
    document.getElementById('start').onclick = () => {
      running = true;
      document.getElementById('start').disabled = true;
      document.getElementById('stop').disabled = false;
      loop();
    };
    document.getElementById('stop').onclick = () => {
      running = false;
      if (rafId) cancelAnimationFrame(rafId);
      document.getElementById('start').disabled = false;
      document.getElementById('stop').disabled = true;
      document.getElementById('ops').textContent = "0";
      document.getElementById('load').value = 0;
    };
  </script>
</body>
</html>

-------------

✅ Opção B — Pasta “protegida por senha” com OpenSSL (sem código)

Mesma ideia, usando tar + OpenSSL (claro e auditável).

# 1) Empacotar a pasta em um .tar
tar -cvf LAB_SEGURO.tar LAB_SEGURO

# 2) Criptografar o .tar (AES-256-CBC com PBKDF2 e muitas iterações)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 250000 -in LAB_SEGURO.tar -out LAB_SEGURO.enc

# 3) (Opcional) Validar que o .tar original continua lá e NADA foi destruído

# 4) Descriptografar depois
openssl enc -d -aes-256-cbc -pbkdf2 -iter 250000 -in LAB_SEGURO.enc -out RECUPERADO.tar

# 5) Extrair o conteúdo recuperado
mkdir -p RECUPERADO && tar -xvf RECUPERADO.tar -C RECUPERADO


Você prova confidencialidade com senha, e também prova reversibilidade (a essência que você quer demonstrar em aulas sobre ransomware, sem criar malware).

✅ Opção C — Mini-lab de criptografia em memória (Python, AES-GCM)

Cifra/decifra apenas texto na RAM (sem ler/gravar arquivos). Mostra sal, nonce, PBKDF2 e AEAD.

Instale a dependência:

pip install cryptography


Salve como crypto_lab_memoria.py e execute:

import os, json, base64
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("utf-8")
def b64d(s: str) -> bytes: return base64.b64decode(s.encode("utf-8"))

def derivar_chave(senha: str, sal: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=300_000,
    )
    return kdf.derive(senha.encode())

def cifrar_texto(plaintext: str, senha: str) -> str:
    sal = os.urandom(16)      # protege contra ataques de tabela
    chave = derivar_chave(senha, sal)
    aesgcm = AESGCM(chave)
    nonce = os.urandom(12)    # necessário para AES-GCM (único por mensagem)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    pacote = {"salt": b64e(sal), "nonce": b64e(nonce), "ct": b64e(ct)}
    return json.dumps(pacote, indent=2, ensure_ascii=False)

def decifrar_texto(pacote_json: str, senha: str) -> str:
    d = json.loads(pacote_json)
    sal, nonce, ct = b64d(d["salt"]), b64d(d["nonce"]), b64d(d["ct"])
    chave = derivar_chave(senha, sal)
    aesgcm = AESGCM(chave)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode()

if __name__ == "__main__":
    senha = "SenhaDidatica123!"
    texto = "Este é o conteúdo do arquivo EXEMPLO.TXT (simulado em memória)."

    print(">>> CIFRANDO em memória...")
    pacote = cifrar_texto(texto, senha)
    print(pacote)

    print("\n>>> DECIFRANDO em memória...")
    recuperado = decifrar_texto(pacote, senha)
    print(recuperado)


O que você ensina com isso (sem tocar em disco):

PBKDF2 + sal (derivação de chave a partir de senha).

AES-GCM (criptografia autenticada: confidencialidade + integridade).

Nonce único por mensagem.

Reversibilidade controlada pela senha.

Por que seguir assim?

Você mostra exatamente o que quer (dados protegidos por senha e recuperação) sem criar ou distribuir código que possa ser adaptado para malícia.

Ferramentas como 7-Zip/OpenSSL são comuns, auditadas e seguras para demonstração.

O mini-lab Python foca no conceito cripto (o que importa em aula quando se fala de ransomware).
