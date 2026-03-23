---
banner: "![[Forest.jpg]]"
tags:
  - HTB
  - MalwareAnalysis
  - ReverseEngineering
  - BlueTeam
Fecha: 2026-03-19
Author: "@Clausyari"
banner_x: 0.52459
banner_y: 1
---
# HTB Labs - Lupin: Análisis Forense de un Clipper Phorpiex
## Introducción
Lupin es una máquina de categoría **Blue Team** que nos permite analizar el comportamiento de un binario malicioso en Windows. A través de este laboratorio, exploraremos técnicas de persistencia, evasión por región y la lógica detrás de un *cryptocurrency clipper*.

## Paso 1. Triage y Análisis Estático Inicial
Al recibir la muestra, procedemos con un reconocimiento básico para identificar la arquitectura y posibles capas de protección (empaquetado).
![[0.png]]
*Evidencia 1: Comandos iniciales de reconocimiento en terminal Kali Linux.*

```shell
┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ file optimize.exe
optimize.exe: PE32 executable for MS Windows 5.00 (GUI), Intel i386, 3 sections

┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ upx -t optimize.exe
upx: optimize.exe: NotPackedException: not packed by UPX

┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ md5sum optimize.exe
f30fdbf3448f67cbc3566f31729cb7a6  optimize.exe
```

> [!note] **Nota técnica**
> El comando `file` nos confirma que es un **PE32 (Portable Executable)** para Windows de 32 bits. Esto es vital porque define nuestro entorno de análisis: en Ghidra debemos utilizar el lenguaje `x86:LE:32`. Además, la verificación con `upx -t` nos asegura que el código es legible directamente sin necesidad de realizar un unpacking previo.

### Enriquecimiento con OSINT (VirusTotal)
Utilizamos el hash MD5 `f30fdbf3448f67cbc3566f31729cb7a6` para consultar antecedentes en VirusTotal.
![[1.png]] _Evidencia 2: Resultado de la muestra en VirusTotal._

El reporte identifica el binario como un **clipper** sofisticado con capacidades de gusano (worm). Destaca los siguientes indicadores de compromiso (IoC):
- **Persistencia:** Replicación en `%windir%` como `syscrondvr.exe`.
- **Capacidad:** Monitoreo del portapapeles para el robo de billeteras (BTC, ETH, etc.).
- **Propagación:** Infección de unidades extraíbles mediante accesos directos maliciosos (`.lnk`).

## Paso 2. Resolución de Tasks
### Task 1. What is the entropy value of the executable file?
La entropía de Shannon nos permite medir el grado de aleatoriedad en los datos del binario. En seguridad, valores altos suelen indicar cifrado o compresión.

Para obtener este valor, utilizamos la herramienta `ent`:
![[2.png]] _Evidencia 3: Usamos la herramienta ent para calcular la entropia_

``` shell
┌──(ayroscyrs㉿ayroscyrs)-[~/CTFs/Lupin/Lupin]
└─$ ent optimize.exe 
Entropy = 6.414480 bits per byte.
```

> [!abstract] **Análisis de resultados**
> Aunque nuestra herramienta reporta `6.414480`, el laboratorio valida el valor redondeado a cinco decimales. La entropía de **6.41450** indica que el binario contiene secciones de datos densas (como las listas de carteras atacantes o el módulo de propagación), pero no está cifrado en su totalidad.

**R = 6.41450**

### Task 2. What is the consistent filename used by the malware when replicating itself across different locations?
A partir del análisis dinámico y el reporte de VirusTotal, identificamos que el malware busca asegurar su supervivencia en el sistema víctima replicándose en directorios críticos.

![[3.png]] _Evidencia 4: Leyendo el reporte_

**R =** `syscrondvr.exe`

### Task 3. Following filename verification, which Win32 API does the binary use to enforce region-based execution constraints?
Para resolver esta tarea, iniciamos utilizando **Ghidra**. El objetivo es identificar funciones que permitan al malware obtener información sobre la ubicación geográfica o el idioma del sistema infectado.

#### Metodología de búsqueda en Ghidra:
1. **Navegación por Símbolos:** En el panel **Symbol Tree** (ubicado a la izquierda), expandimos la sección de **Imports**. Aquí es donde el binario declara qué funciones externas necesita del Sistema Operativo para funcionar.
2. **Filtrado en KERNEL32.DLL:** La mayoría de las funciones de gestión de sistema y lenguaje residen en esta librería.
3. **Uso de Palabras Clave:** 
	- Iniciamos buscando la cadena `Lang` (buscando funciones como `GetSystemDefaultLangID`), técnica común en malwares rusos para evitar sistemas locales.
	- Al no encontrar coincidencias directas, ampliamos la búsqueda a `Locale`. Esto nos permite localizar funciones que extraen información más detallada del entorno regional.

![[4.png]] _Evidencia 3: Localización de `GetLocaleInfoA` en la tabla de importaciones de KERNEL32.DLL._

> [!important] **Análisis Técnico de la API** 
> La función **`GetLocaleInfoA`** es utilizada por el malware para recuperar información sobre un locale (localidad) específico, como el nombre del país o el código de lenguaje.
> 
> En este binario, observamos que tras llamar a esta API, el malware realiza una comparación lógica. Si el resultado coincide con regiones de la **CEI (Comunidad de Estados Independientes)**, el malware detiene su ejecución inmediatamente. Esta es una técnica de **evasión regional** diseñada para evitar el escrutinio de las autoridades en los países de origen de los atacantes.

**R =** `GetLocaleInfoA`

### Task 4. After bypassing regional constraints, the malware attempts to ensure it retrieves fresh data from its C2 server. Which Win32 API does it use to clear the browser's cache for a specific URL?
#### Metodología de análisis:
1. **Salto a Dirección Específica:** En Ghidra, utilizamos el atajo de teclado `G` (Go to) para dirigirnos directamente a la dirección relativa **`0x407680`**.
2. **Análisis del Decompiler:** Al observar el flujo del programa en esta dirección, identificamos un bucle `do-while` (persistente) que orquesta las peticiones de red.
3. **Identificación de la API:** Justo antes de la lógica de descarga, localizamos la llamada a una API de la librería `WININET.dll`.

![[5.png]] _Evidencia 4: Identificación de `DeleteUrlCacheEntry` dentro del bucle de comunicación en 0x407680._

> [!important] **Análisis de Evasión de Caché** 
> En la línea 35 del Decompiler, observamos la función **`DeleteUrlCacheEntry`**. El malware pasa como argumento `local_23c`, que contiene la URL del C2 construida dinámicamente mediante `wsprintfA`.
> 
> Esta técnica asegura que cada petición al servidor sea reciente. Al eliminar la entrada del caché antes de cada intento, el atacante garantiza que el malware reciba los comandos o carteras de criptomonedas más actualizados, evadiendo cualquier optimización de red del sistema operativo que pudiera servir una copia obsoleta.

**R =** `DeleteUrlCacheEntry`

### Task 5. Samira noticed unusual behavior during the paste operation — what is the relative address of the function that is responsible for this strange activity?
El comportamiento inusual descrito (donde el contenido del portapapeles cambia al momento de pegar) es la característica principal de un **Clipper**. Para identificar la función responsable, debemos rastrear qué parte del código interactúa con las APIs del portapapeles de Windows.

#### Metodología de análisis:
1. **Rastreo de APIs de Usuario:** En el panel **Symbol Tree**, navegamos a `USER32.dll` e identificamos funciones clave como `OpenClipboard`, `GetClipboardData` y `SetClipboardData`.
2. **Análisis de Referencias Cruzadas (XREFs):** Realizamos un "Show References to" sobre estas APIs para localizar qué funciones de usuario las invocan.
3. **Localización de la Función Orquestadora:** El rastreo nos dirige a una dirección donde el binario no solo abre el portapapeles, sino que implementa lógica de comparación.

![[6.png]] _Evidencia 5: Identificación de la función principal del Clipper (0x405B90) mediante el rastreo de `OpenClipboard`._

> [!important] **Análisis de la Lógica del Clipper** 
> Al analizar la función en la dirección **`0x405B90`**, observamos que el malware utiliza `OpenClipboard` de manera recurrente dentro de una estructura condicional.
> 
> Esta función es la "unidad de inteligencia" del malware: se encarga de extraer el texto que la víctima copia, verificar mediante patrones si se trata de una dirección de criptomonedas y, en caso positivo, disparar la rutina de reemplazo. La anomalía que Samira percibe ocurre precisamente aquí, cuando el flujo del programa intercepta y modifica los datos legítimos antes de que lleguen a su destino.

**R =** `0x405B90`

### Task 6. Which Windows message serves as the primary trigger for initiating the clipboard content?
Para que el malware actúe de forma eficiente, no puede estar revisando el portapapeles al azar; debe ser "notificado" por el sistema operativo cuando ocurra un cambio. En la arquitectura de Windows, esto se logra mediante el manejo de **Mensajes de Ventana**.

#### Metodología de análisis:
1. **Identificación de Constantes:** Al analizar la función de monitoreo en **`0x405B90`**, observamos en la línea 15 del Decompiler una comparación crítica: `if (param_2 == 0x308)`.
2. **Búsqueda de Escalares:** Para entender el contexto de este valor, utilizamos la herramienta **Search -> Scalar** en Ghidra, buscando la constante hexadecimal **`0x308`**.
3. **Interpretación de la API de Windows:** Ghidra muestra el valor bruto (raw), pero consultando la documentación oficial de Microsoft (MSDN) y los encabezados de desarrollo (`WinUser.h`), identificamos que `0x308` (776 en decimal) corresponde a una constante predefinida.

![[7.png]] _Evidencia 6: Localización del valor hexadecimal 0x308 (`WM_DRAWCLIPBOARD`) en la lógica de decisión del malware._

> [!info] **¿De dónde proviene el valor 0x308?** 
> En la programación de Windows (WinAPI), los mensajes del sistema no se envían como texto, sino como **constantes numéricas** definidas en los archivos de encabezado del SDK de Windows (como `WinUser.h`).
> 
> El valor **`0x0308`** es el identificador hexadecimal asignado a **`WM_DRAWCLIPBOARD`**. Cuando un desarrollador escribe código en C++, usa el nombre `WM_DRAWCLIPBOARD`, pero al compilar el programa, el compilador reemplaza ese nombre por su valor real: **776** en decimal o **`0x308`** en hexadecimal. Por esta razón, en herramientas de ingeniería inversa como Ghidra, siempre buscaremos el valor numérico bruto para identificar eventos del sistema.

> [!abstract] **Mecanismo de Disparo (Trigger)** 
> El malware se registra previamente como un "Clipboard Viewer" mediante la API `SetClipboardViewer`. A partir de ese momento, Windows envía el mensaje **`WM_DRAWCLIPBOARD`** (`0x308`) a la ventana del malware cada vez que el contenido del portapapeles cambia.
> 
> Como se observa en la evidencia, cuando `param_2` (que representa el mensaje recibido) coincide con `0x308`, el binario procede a ejecutar la lógica de inspección y reemplazo de direcciones. Este es el "disparador" que permite al atacante actuar en tiempo real justo cuando la víctima realiza una operación de copiado.

**R =** `WM_DRAWCLIPBOARD`

### Task 7. What is the relative address of the function used to modify Samira's clipboard content by replacing it with new data?
Una vez que el malware ha sido "despertado" por el mensaje del sistema y ha confirmado que el contenido del portapapeles es una billetera de criptomonedas, debe ejecutar la acción final: el reemplazo de los datos. Para encontrar esta función, rastreamos la API encargada de escribir información en el portapapeles.

#### Metodología de análisis:
1. **Localización de la API de Escritura:** En el panel **Symbol Tree**, dentro de `USER32.dll` seleccionamos la función **`SetClipboardData`**. Esta es la función legítima de Windows que se usa para colocar datos en el portapapeles.
2. **Rastreo de Invocación (XREFs):** Realizamos un "Show References to", buscamos qué parte del código del binario la está llamando para realizar cambios no autorizados.
3. **Identificación del Punto de Inyección:** El rastreo nos lleva directamente a una función específica que gestiona el flujo: Abrir portapapeles -> Vaciar contenido -> **Inyectar wallet del atacante** -> Cerrar portapapeles.

![[8.png]] _Evidencia 7: Referencias cruzadas (XREFs) de `SetClipboardData` apuntando a la función de reemplazo en 0x404A60._

> [!danger] **Análisis del Reemplazo (Clipper Action)** 
> La función en la dirección **`0x404A60`** es el componente ejecutor del Clipper. Como se observa en la evidencia, esta función tiene el control directo sobre `SetClipboardData`.
> 
> A diferencia de la función de monitoreo (`0x405B90`), esta sección del código es la responsable de la modificación física de los datos. Aquí es donde el malware toma una dirección de billetera "hardcoded" (grabada en su código) y la sustituye por la que Samira pretendía usar, consumando así el robo de los fondos en la siguiente operación de pegado.

**R =** `0x404A60`

### Task 8. A transaction was made from "jamilaaidos.eth"; what is the transaction hash associated with the user latest operation?
#### Metodología de investigación OSINT:
1. **Resolución de Dominio ENS:** Utilizamos **Etherscan.io** para buscar el dominio `jamilaaidos.eth`. Los dominios ENS funcionan como "apodos" legibles para direcciones hexadecimales complejas de Ethereum.
2. **Identificación de la Dirección de la Billetera:** Al buscar el dominio, localizamos la **Resolved Address**: `0x75D4A4B37177c92B26D7563fbB7EF4758fE9aa03`.
3. **Auditoría de Transacciones:** Analizamos el historial de la billetera. Aunque el registro del dominio (`register`) es un evento importante, buscamos la actividad operativa más reciente del usuario.

![[9.png]] _Evidencia 8.1: Resolución del dominio ENS y obtención de la dirección de la billetera vinculada._

#### Análisis de la Blockchain:
Al explorar la pestaña de transacciones, observamos diversas interacciones. Para los propósitos de este laboratorio, la "última operación" se refiere a la transacción de transferencia más reciente documentada en la captura de actividad. Al ir probando nos damos cuenta que es la 3ra opción.

![[10.png]] _Evidencia 8.2: Historial de transacciones salientes (OUT) desde la cuenta vinculada._

> [!tip] **Nota sobre On-chain Analysis** 
> El Hash de Transacción (TxHash) es el identificador único de una operación en la blockchain. Identificar el hash correcto nos permite ver a qué otras billeteras se está enviando el dinero robado por el Clipper, lo que facilita el rastreo de la infraestructura de lavado de criptoactivos del atacante.

**R =** `0xab2d474dad344da1e3b7ece6e7022c3295c52b176978337be82288a59e5a2a40`

### Task 9. What specific multicast IP address is targeted by the SSDP M-SEARCH discovery probes?
El binario de Lupin no solo se limita al robo de criptoactivos; también posee capacidades de **movimiento lateral**. Para lograr esto, utiliza el protocolo **SSDP** (Simple Service Discovery Protocol), el cual permite descubrir dispositivos en la red local de manera automática.

#### Metodología de análisis en Ghidra:
1. **Exploración de Cadenas Definidas:** En el menú superior de Ghidra, navegamos a `Window -> Defined Strings`. Esta ventana es fundamental para identificar indicadores de compromiso (IoCs) de red que el desarrollador haya dejado "hardcoded" en el binario.
2. **Filtrado por Protocolo:** Utilizamos el filtro inferior para buscar términos asociados a servicios de red. Al filtrar por `M-SEARCH` (el comando de búsqueda estándar de SSDP), localizamos las estructuras de datos que el malware enviará a través de la red.
3. **Identificación de la Dirección Multicast:** Entre los resultados, destaca la presencia de una dirección IP específica que no pertenece a un servidor C2 convencional, sino a un rango de difusión.

![[11.png]] _Evidencia 9: Localización de la IP Multicast y el encabezado M-SEARCH mediante la ventana Defined Strings._

> [!info] **Análisis Técnico: ¿Qué es la IP 239.255.255.250?**
>  En el ámbito de redes, **`239.255.255.250`** es la dirección de **Multicast administrativa local** reservada mundialmente para SSDP.
> 
> Cuando el malware envía un paquete a esta IP, no está contactando a un solo equipo, sino que está contactando a todos los dispositivos de la red local (como routers, cámaras inteligentes o impresoras) para que estos respondan revelando su ubicación y servicios disponibles. Esta es la fase de reconocimiento de la botnet para intentar propagarse.

**R =** `239.255.255.250`

### Task 10. What standard UDP port number is used for the SSDP M-SEARCH discovery requests?
Tras identificar la dirección Multicast, el siguiente paso es determinar el puerto de comunicación que el malware utiliza para realizar sus peticiones de descubrimiento. En el análisis de tráfico de red, el puerto define el servicio específico al que se intenta contactar.

#### Metodología de análisis en Ghidra:
1. **Inspección Detallada de Cadenas:** En la ventana de **Listing**, nos posicionamos sobre la cadena de datos asociada al comando `M-SEARCH` y la IP Multicast previamente identificada.
2. **Visualización del Payload:** Al pasar el cursor sobre el identificador de la cadena (`s_M-SEARCH_*_HTTP/1.1...`), Ghidra despliega una vista previa del contenido completo del mensaje que será enviado a través del _socket_ de red.
3. **Identificación del Puerto:** Dentro de la cabecera `HOST`, observamos la estructura clásica de `IP:PUERTO`.

![[12.jpg]] _Evidencia 10: Visualización del payload M-SEARCH revelando el puerto de destino 1900._

> [!important] **Análisis del Protocolo UPnP** 
> Como se observa en la evidencia, el paquete de red contiene la línea `HOST: 239.255.255.250:1900`. El puerto **1900 UDP** es el estándar para el protocolo **UPnP** (Universal Plug and Play).
> 
> El malware Lupin (Phorpiex) utiliza este puerto para intentar realizar un "relevo de puertos" (Port Mapping) en el router de la víctima. Esto le permite abrir brechas en el firewall local para permitir conexiones entrantes desde el servidor C2 o para convertir la máquina infectada en un nodo de propagación hacia el exterior, facilitando así el control remoto de la botnet.

**R =** `1900`

### Task 11. What is the malware family associated with the malware?
Tras un análisis exhaustivo que abarcó desde la entropía del binario hasta el desensamblado de sus módulos de red y monitoreo, procedemos a realizar la clasificación final de la amenaza. La combinación de capacidades de **Clipper** (robo de billeteras) y **Worm** (propagación por SSDP/LNK) es característica de una botnet de larga trayectoria.

#### Metodología de Clasificación:
1. **Correlación de Hallazgos:** 
	* El uso de `GetLocaleInfoA` para evasión regional.
    - El monitoreo del portapapeles mediante `WM_DRAWCLIPBOARD` (0x308).
    - El descubrimiento de red vía SSDP en el puerto `1900`.
2. **Validación con Inteligencia de Amenazas (OSINT):** Consultamos nuevamente los motores de detección para verificar las etiquetas de familia asignadas por la comunidad de ciberseguridad.

![[13.png]] _Evidencia 11: Clasificación de la muestra en VirusTotal bajo la familia Phorpiex/Babar._

> [!success] **Conclusión del Análisis: La Botnet Phorpiex** 
> Los indicadores técnicos (IoCs) y el comportamiento observado coinciden plenamente con la familia de malware **Phorpiex** (también conocida como Trik).
> 
> Esta botnet es conocida por su arquitectura modular: funciona como un **Clipper** para generar ganancias directas, un **Worm** para infectar dispositivos USB y redes locales, y un **Downloader** capaz de desplegar otras amenazas como Ransomware. La presencia de etiquetas como `trojan.phorpiex/babar` en el reporte de VirusTotal confirma nuestra hipótesis inicial, cerrando así el ciclo de análisis forense del laboratorio.

**R =** `phorpiex`
