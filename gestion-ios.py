import datetime
import sys
import os

DB_PATH = r'D:\Documentos\BtrConsulting\LaCaja\\'
DB_PATH_FIREWALL = DB_PATH + r'dbios\db_fwall.txt'
DB_PATH_PROXY = DB_PATH + r'dbios\db_proxy.txt'
DB_PATH_ANTISPAM = DB_PATH + r'dbios\db_spam.txt'

OUTPUT_PATH = r'D:\Documentos\BtrConsulting\LaCaja\iosParaEnviar\\'
OUTPUT_FIREWALL: str = r'_IOS_FIREWALL.txt'
OUTPUT_PROXY = r'_IOS_PROXY.txt'
OUTPUT_ANTISPAM = r'_IOS_ANTISPAM.txt'

def clear():
    os.system('cls')

def lastInsert(tipo):
    if tipo == 'F':
        path = DB_PATH_FIREWALL
    elif tipo == 'P':
        path = DB_PATH_PROXY
    else:
        path = DB_PATH_ANTISPAM

    line = ''

    try:
        file = open(path, 'r')
        rows = file.readlines()
        if rows:
            line = rows[-1]            
        file.close()

    except FileNotFoundError:
        file = open(path, 'w')
        file.close()

    return line

def lastInserted():
    print('\n------Last Row(s) Inserted------\n')
    print(' Type\t Id\t   Day\t\t      Name\t\t\tValue\n')
    print(' ' + lastInsert('F'))
    print(' ' + lastInsert('P'))
    print(' ' + lastInsert('A'))
    input()
    clear()
    menu()

def generarFecha(unaFecha):
    monthDict = {
        "January": "1",
        "February": "2",
        "March": "3",
        "April": "4",
        "May": "5",
        "June": "6",
        "July": "7",
        "August": "8",
        "September": "9",
        "October": "10",
        "November": "11",
        "December": "12"
    }

    for oneMonth in monthDict:
        unaFecha = unaFecha.replace(oneMonth, monthDict[oneMonth])

    unaFecha = unaFecha.split()
    unaFecha = unaFecha[0].strip() + '/' + unaFecha[1].strip() + '/' + unaFecha[2].strip()
    # unaFecha = datetime.date(int(unaFecha[2]), int(unaFecha[1]), int(unaFecha[0]))
    return unaFecha

def cargarBloqueo():
    print("----------New Blocking Request---------\n")
    text = []
    flag = False
    while not flag:
        linea = input()
        if linea != "":
            if linea.find("*") == -1:
                text.append(linea)
            else:
                flag = True
    clear()
    text.remove('Dear All,')
    text[0] = generarFecha(text[0])
    text[1] = text[1].split()[2]
    
    switchFun = {
        'firewall': createFirewallRequest,
        'proxy': createProxyRequest,
        'antispam': createAntispamRequest
    }

    for word, fun in switchFun.items():
        if text[2].find(word) != -1:
            fun(text)
            break

def traerUltimoId(tipo):
    idrow = 0
    if tipo == 'F':
        path = DB_PATH_FIREWALL
    elif tipo == 'P':
        path = DB_PATH_PROXY
    else:
        path = DB_PATH_ANTISPAM
    try:
        file = open(path, 'r')
        rows = file.readlines()
        if rows:
            rows.reverse()
            for row in rows:
                line = row.split('\t')
                if line[0] == tipo:
                    idrow = int(line[1])
                    break
        file.close()
    except FileNotFoundError:
        file = open(path, 'w')
        file.close()

    return idrow

def guardarInsert(toInsert, tipo):
    if tipo == 'F':
        path = DB_PATH_FIREWALL
    elif tipo == 'P':
        path = DB_PATH_PROXY
    else:
        path = DB_PATH_ANTISPAM

    print('------Insert Row(s)------\n')
    print('*' * 80)
    print(toInsert)
    print('*' * 80)
    a = input('\nENTER --> CONTINUE \t C --> CANCEL\n')
    if a == 'c' or a == 'C':
        print('------Row(s) not saved------\n')
    else:
        file = open(path, 'a')
        file.write(toInsert)
        file.close()
        print('------Row(s) saved successfully------\n')

    input()
    clear()
    menu()

def createFirewallRequest(unText):
    fecha = unText.pop(0)
    idSim = unText.pop(0)
    unText.pop(0)
    toInsert = ""
    idEvent = traerUltimoId('F')
    idEvent += 1
    for ip in unText:
        row = 'F\t'
        row += str(idEvent)
        row += '\t'
        row += fecha
        row += '\t'
        row += idSim
        row += '\t'
        row += ip[1:-1]
        row += '\n'

        toInsert += row
        idEvent += 1
    guardarInsert(toInsert, 'F')

def createProxyRequest(unText):
    fecha = unText.pop(0)
    idSim = unText.pop(0)
    unText.pop(0)
    toInsert = ""
    idEvent = traerUltimoId('P')
    idEvent += 1
    for domain in unText:
        row = 'P\t'
        row += str(idEvent)
        row += '\t'
        row += fecha
        row += '\t'
        row += idSim
        row += '\t'
        row += domain.split(': ')[0].strip()
        row += '\t'
        row += domain.split(': ')[1].replace('[.]', '.').strip()
        row += '\n'

        toInsert += row
        idEvent += 1
    guardarInsert(toInsert, 'P')

def createAntispamRequest(unText):
    fecha = unText.pop(0)
    idSim = unText.pop(0)
    unText.pop(0)
    toInsert = ""
    idEvent = traerUltimoId('A')
    idEvent += 1
    for domain in unText:
        row = 'A\t'
        row += str(idEvent)
        row += '\t'
        row += fecha
        row += '\t'
        row += idSim
        row += '\t'
        row += domain.split(': ')[0].strip()
        row += '\t'
        row += domain.split(': ')[1].replace('[.]', '.').strip()
        row += '\n'

        toInsert += row
        idEvent += 1
    guardarInsert(toInsert, 'A')

def generarReporteSemanal():
    
    print('------Generating New Report------\n')
    repoFirewall()
    repoProxy()
    repoSpam()  
    input()  
    clear()  
    menu()

def levantarFilas(tipo):
    if tipo == 'F':
        path = DB_PATH_FIREWALL
    elif tipo == 'P':
        path = DB_PATH_PROXY
    elif tipo == 'A':
        path = DB_PATH_ANTISPAM
    else:
        print('Error En Tipo levantar filas')
    
    sevenDays = datetime.timedelta(days=7)
    today = datetime.date.today()
    firstDay = today - sevenDays

    #levanto el Archivo
    try:
        file = open(path,'r')
        rows = file.readlines()
        devolver = []
        if rows:
            rows.reverse()
            for row in rows:
                aux = row
                fecha = aux.split('\t')[2]
                fecha = fecha.split('/')
                fecha = datetime.date(int(fecha[2]), int(fecha[1]), int(fecha[0]))
                if fecha < today:
                    if fecha >= firstDay:
                        devolver.append(row)
                    else:
                        break
        file.close()
        devolver.reverse()
        return devolver
    except FileNotFoundError:
        print('Archivo a levantar no Existe')
        return []     

def repoFirewall():
    
    formatoFecha = '%d%b%Y'   
    today = datetime.date.today()
    print(' IOS-FIREWALL-' +  today.strftime(formatoFecha)+ ' -->',flush=True, end='' )
    rows = levantarFilas('F')
    filasFinales = []
    if not rows:
        print('\n-El Archivo a leer no existe o esta vacio-')
        menu()
    for row in rows:
        row = row.split('\t')
        aux = 'edit "IPPub_Atac' + row[1] + '"\nset subnet ' + row[4][:-1] + ' 255.255.255.255\nnext\n'
        filasFinales.append(aux)
    path = OUTPUT_PATH + today.strftime(formatoFecha) + OUTPUT_FIREWALL
    fileFire = open(path,'w')
    fileFire.writelines(filasFinales)
    fileFire.close()
    print(' Done\n',flush=True)

def repoProxy():
    formatoFecha = '%d%b%Y'  
    today = datetime.date.today()
    print(' IOS-PROXY-' +  today.strftime(formatoFecha)+ ' -->',flush=True, end='' )
    rows = levantarFilas('P')
    filasFinales = []
    if not rows:
        print('\n-El Archivo a leer no existe o esta vacio-')
        menu()
    for row in rows:
        row = row.split('\t')
        aux = 'edit "DOMPub_Atac' + row[1] + '"\nset type fqdn\nset fqdn "' + row[5][:-1] + '"\nnext\n'
        filasFinales.append(aux)
    path = OUTPUT_PATH + today.strftime(formatoFecha) + OUTPUT_PROXY
    fileFire = open(path,'w')
    fileFire.writelines(filasFinales)
    fileFire.close()
    print(' Done\n',flush=True)

def repoSpam():
    formatoFecha = '%d%b%Y'   
    today = datetime.date.today()
    print(' IOS-ANTISPAM-' +  today.strftime(formatoFecha)+ ' -->',flush=True, end='' )
    rows = levantarFilas('A')
    filasFinales = []
    if not rows:
        print('\n-El Archivo a leer no existe o esta vacio-')
        menu()
    for row in rows:
        row = row.split('\t')
        aux = row[4] + '\t' + row[5]
        filasFinales.append(aux)
    path = OUTPUT_PATH + today.strftime(formatoFecha) + OUTPUT_ANTISPAM
    fileFire = open(path,'w')
    fileFire.writelines(filasFinales)
    fileFire.close()
    print(' Done\n',flush=True)

def indice():
    print('*' * 80)
    print('*' * 80)
    print('''         *******                 **        **
        /**////**               /**       // 
        /**   /**   ******      /** ****** **
        /*******   **////**  ******//**//*/**
        /**///**  /**   /** **///** /** / /**
        /**  //** /**   /**/**  /** /**   /**
        /**   //**//****** //******/***   /**
        //     //  //////   ////// ///    // 
            ''')
    print('*' * 80)
    print('*' * 80)
    print('\n------Instrucciones Generales de Uso------')
    print('''
    1- Subir el payload del mail
    2- Luego  agrega '*' en nueva linea para indicar el corte 
    3- Verificar la integridad de los datos, antes de agregarlo a la BD
    4- Generar el ultimo reporte Semanal
    5- Para obtenerlos se debe crear carpeta iosParaEnviar
    6- Se crean 3 reportes separados Firewall - Proxy - Antispamm
    
    ------Gracias por utilizar esta herramienta------
    ''')
    print('*' * 80)
    input()
    clear()
    menu()

def default():
    print("------Ups, try Again------")
    input()
    clear()
    menu()

def menu():
    formatoFecha = '%a %d %B %y'
    sevenDays = datetime.timedelta(days=7)
    today = datetime.date.today()
    print('\n-----IOS Management La Caja Seguros-----\n')
    print(' 1- Add a new Blocking Request\n'
          ' 2- Create new Reports from ', (today - sevenDays).strftime(formatoFecha), " to ",
          today.strftime(formatoFecha), '\n'
                                        ' 3- Last Blocking Requests Inserted\n'
                                        ' 4- Help..\n'
                                        ' 0- Exit\n')

    opcion = input()
    clear()

    try:
        opcion = int(opcion)
    except ValueError:
        opcion = 0
        default()

    options = {
        1: cargarBloqueo,
        2: generarReporteSemanal,
        3: lastInserted,
        4: indice,
        0: sys.exit

    }
    options.get(opcion, default)()



#inicio
menu()