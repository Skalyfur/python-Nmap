import subprocess
import re
   
def clasificar_puertos(ports):
    """
    Clasificación por riesgo:   
    ALTA → acceso remoto / datos críticos
    MEDIA → servicios expuestos
    BAJA → servicios auxiliares
    """

    alta_puertos = ["21", "22", "23", "139", "445", "512", "513", "514", "1524", "2049", "3306", "5432", "5900"]
    media_puertos = ["25", "53", "80", "1099", "2121", "8009"]

    alta, media, baja = [], [], []

    for port, service in ports:
        num = port.split("/")[0]

        if num in alta_puertos:
            alta.append((port, service))
        elif num in media_puertos:
            media.append((port, service))
        else:
            baja.append((port, service))

    return alta, media, baja


def analizar_riesgos(ports):
    """
    Genera alertas simples basadas en puertos detectados
    """

    alertas = []

    for port, service in ports:
        num = port.split("/")[0]

        if num == "23":
            alertas.append("-Telnet detectado (sin cifrado, muy inseguro)")
        elif num == "21":
            alertas.append("-FTP detectado (credenciales en texto plano)")
        elif num == "22":
            alertas.append("-SSH expuesto (posible acceso remoto)")
        elif num == "445":
            alertas.append("-SMB expuesto (alto riesgo en red)")
        elif num == "3306":
            alertas.append("-MySQL expuesto (base de datos accesible)")
        elif num == "5432":
            alertas.append("-PostgreSQL expuesto")
        elif num == "5900":
            alertas.append("-VNC activo (control remoto)")
        elif num == "80":
            alertas.append("ℹ️ Servicio web activo (revisar seguridad)")

    return list(set(alertas))  


def escanear_objetivo(target):
    print(f"\n[+] Escaneando: {target}\n")

    try:
        resultado = subprocess.check_output(
            ["nmap", "-sS", "-T4", target],
            text=True
        )
    except subprocess.CalledProcessError:
        print("[-] Error ejecutando Nmap")
        return

    # Extraer puertos abiertos
    ports = re.findall(r"(\d+/tcp)\s+open\s+([\w\-]+)", resultado)

    if not ports:
        print("[-] No se encontraron puertos abiertos")
        return

    # Clasificar
    alta, media, baja = clasificar_puertos(ports)

    print("========== RESULTADOS ==========\n")

    # ALTA
    print("[ALTA] (Acceso crítico)")
    for port, service in alta:
        print(f"  - {port} → {service}")
    print()

    # MEDIA
    print("[MEDIA] (Servicios expuestos)")
    for port, service in media:
        print(f"  - {port} → {service}")
    print()

    # BAJA
    print("[BAJA] (Otros servicios)")
    for port, service in baja:
        print(f"  - {port} → {service}")
    print()

    #  ALERTAS
    print("========== ALERTAS ==========\n")
    alertas = analizar_riesgos(ports)

    if alertas:
        for alerta in alertas:
            print(alerta)
    else:
        print("[+] No se detectaron riesgos evidentes")


if __name__ == "__main__":
    ip = input("Ingresa la IP objetivo: ")
    escanear_objetivo(ip)
