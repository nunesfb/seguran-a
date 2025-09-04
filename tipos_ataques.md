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

-----


