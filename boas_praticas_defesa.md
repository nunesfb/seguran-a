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
