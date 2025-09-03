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
