import csv
import time
from datetime import datetime

import dns.exception
import dns.flags
import dns.name
import dns.resolver

# Lista de dominios a analizar
DOMINIOS_A_ANALIZAR = [
    # Gubernamental
    "gob.mx",
    "sat.gob.mx",
    "presidencia.gob.mx",
    "hacienda.gob.mx",
    "economia.gob.mx",
    "salud.gob.mx",
    "sep.gob.mx",
    "imss.gob.mx",
    "ine.mx",
    "scjn.gob.mx",
    # Academico
    "unam.mx",
    "tec.mx",
    "ipn.mx",
    "uam.mx",
    "udg.mx",
    "buap.mx",
    "uanl.mx",
    "colmex.mx",
    "itam.mx",
    "anahuac.mx",
    # Financiero
    "santander.com.mx",
    "bb.com.mx",
    "banamex.com.mx",
    "bbva.mx",
    "banorte.com.mx",
    "hsbc.com.mx",
    "scotiabank.com.mx",
    "inbursa.com.mx",
    "banregio.com.mx",
    "afirme.com.mx",
    # Comercio electronico
    "amazon.com.mx",
    "mercadolibre.com.mx",
    "walmart.com.mx",
    "liverpool.com.mx",
    "sears.com.mx",
    "sanborns.com.mx",
    "homedepot.com.mx",
    "costco.com.mx",
    "cyberpuerta.mx",
    "officedepot.com.mx",
    # Medios de comunicacion
    "eluniversal.com.mx",
    "mural.com.mx",
    "proceso.com.mx",
    "jornada.com.mx",
    "excelsior.com.mx",
    "eleconomista.com.mx",
    "expansion.mx",
    "forbes.com.mx",
    "radioformula.com.mx",
    "nmas.com.mx",
]


def obtener_info_algoritmo_y_keysize(key_rrset):
    """Extrae el algoritmo y calcula/estima el tamaño de la llave de los registros DNSKEY."""
    algoritmos = {
        5: "RSASHA1",
        7: "RSASHA1-NSEC3-SHA1",
        8: "RSASHA256",
        10: "RSASHA512",
        13: "ECDSAP256SHA256",
        14: "ECDSAP384SHA384",
        15: "ED25519",
    }
    algoritmos_lista = []
    keysizes_lista = []

    for key in key_rrset:
        nom_alg = algoritmos.get(key.algorithm, f"Alg-{key.algorithm}")
        if nom_alg not in algoritmos_lista:
            algoritmos_lista.append(nom_alg)

        if key.algorithm in [13, 15]:
            bits = "256"
        elif key.algorithm == 14:
            bits = "384"
        elif hasattr(key, "key") and key.algorithm in [5, 7, 8, 10]:
            bits = str(len(key.key) * 8)
        else:
            bits = "Desconocido"

        if bits not in keysizes_lista:
            keysizes_lista.append(bits)

    return ", ".join(algoritmos_lista), ", ".join(keysizes_lista)


def analizar_dominio(dominio_str):
    """Realiza la inspección DNSSEC completa para mapear las columnas del CSV."""
    fila = {
        "Dominio": dominio_str,
        "DNSSEC activo (sí/no)": "no",
        "valida (sí/no)": "no",
        "motivo de fallo si lo hay": "na",
        "NSEC (NSEC/NSEC3/na)": "na",
        "algoritmo": "na",
        "keysize bits": "na",
        "RRset firmadas": "no",
        "DS en zona padre (sí/no)": "no",
        "observaciones adicionales": "",
    }

    dominio = dns.name.from_text(dominio_str)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
    resolver.timeout = 3.0  # Tiempo límite para cada intento individual
    resolver.lifetime = (
        5.0  # Tiempo total de vida de la consulta antes de lanzar Timeout
    )
    resolver.use_edns(0, ednsflags=dns.flags.DO, payload=4096)

    # 1. Verificar registro DS en la zona padre (Protegido contra Timeout)
    tiene_ds = False
    try:
        resolver.resolve(dominio, dns.rdatatype.DS)
        tiene_ds = True
        fila["DS en zona padre (sí/no)"] = "sí"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        fila["DS en zona padre (sí/no)"] = "no"
    except (dns.resolver.Timeout, dns.exception.Timeout):
        fila["motivo de fallo si lo hay"] = "Timeout en consulta DS"
        fila["observaciones adicionales"] = (
            "La consulta del registro DS al servidor padre expiró."
        )
        return fila
    except Exception as e:
        fila["motivo de fallo si lo hay"] = f"Error consulta DS: {type(e).__name__}"
        fila["observaciones adicionales"] = "Error inesperado de red al buscar DS."
        return fila

    # 2. Consultar registros DNSKEY y RRSIG (Protegido contra Timeout)
    try:
        respuesta_dnskey = resolver.resolve(dominio, dns.rdatatype.DNSKEY)
        tiene_dnskey = False

        for rrset in respuesta_dnskey.response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                tiene_dnskey = True
                alg, ksize = obtener_info_algoritmo_y_keysize(rrset)
                fila["algoritmo"] = alg
                fila["keysize bits"] = ksize

            if rrset.rdtype == dns.rdatatype.RRSIG:
                fila["RRset firmadas"] = "sí"

                ahora = time.time()
                firmas_validas = True
                for rrsig in rrset:
                    if not (rrsig.inception <= ahora <= rrsig.expiration):
                        firmas_validas = False
                        fila["motivo de fallo si lo hay"] = (
                            "Firma RRSIG expirada o fuera de rango"
                        )
                        break

                if firmas_validas:
                    fila["valida (sí/no)"] = "sí"

        if tiene_dnskey:
            fila["DNSSEC activo (sí/no)"] = "sí"
            if not tiene_ds:
                fila["valida (sí/no)"] = "no"
                fila["motivo de fallo si lo hay"] = (
                    "Isla de confianza: Sin DS en zona padre"
                )
        else:
            if tiene_ds:
                fila["motivo de fallo si lo hay"] = (
                    "Inconsistencia Crítica (Bogus): DS presente pero sin DNSKEY"
                )

    except dns.resolver.NoAnswer:
        if tiene_ds:
            fila["motivo de fallo si lo hay"] = (
                "Inconsistencia Crítica (Bogus): El padre exige DS pero la zona no responde DNSKEY"
            )
        else:
            fila["motivo de fallo si lo hay"] = "na"
            fila["observaciones adicionales"] = (
                "Dominio tradicional sin firmas criptográficas"
            )
    except (dns.resolver.Timeout, dns.exception.Timeout):
        fila["motivo de fallo si lo hay"] = "Timeout en consulta DNSKEY"
        fila["observaciones adicionales"] = (
            "La consulta DNSKEY expiró por falta de respuesta del servidor."
        )
        return fila
    except Exception as e:
        fila["motivo de fallo si lo hay"] = f"Error DNSKEY: {type(e).__name__}"
        return fila

    # 3. Detectar mecanismo de negación autenticada (NSEC o NSEC3) - CON CAPTURA DE TIMEOUT CRÍTICA
    if fila["DNSSEC activo (sí/no)"] == "sí":
        subdominio_falso = dns.name.from_text(f"prueba-inexistencia.{dominio_str}")
        try:
            resolver.resolve(subdominio_falso, dns.rdatatype.A)
        except dns.resolver.NXDOMAIN as e:
            auth_records = e.responses().values() if hasattr(e, "responses") else []
            mecanismo_detectado = "na"
            for response in auth_records:
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        mecanismo_detectado = "NSEC"
                    elif rrset.rdtype == dns.rdatatype.NSEC3:
                        mecanismo_detectado = "NSEC3"
            fila["NSEC (NSEC/NSEC3/na)"] = mecanismo_detectado
        except (dns.resolver.Timeout, dns.exception.Timeout):
            # Aquí es donde fallaba con el IPN, ahora pasa de largo registrando el suceso
            fila["NSEC (NSEC/NSEC3/na)"] = "na"
            fila["observaciones adicionales"] = (
                fila["observaciones adicionales"] + " | Timeout al detectar NSEC/NSEC3."
            ).strip(" | ")
        except Exception as e:
            fila["NSEC (NSEC/NSEC3/na)"] = "na"
            fila["observaciones adicionales"] = (
                fila["observaciones adicionales"] + f" | Error NSEC: {type(e).__name__}"
            ).strip(" | ")

    return fila


def generar_reporte_csv():
    nombre_csv = "reporte_infraestructura_dnssec.csv"

    columnas = [
        "Dominio",
        "DNSSEC activo (sí/no)",
        "valida (sí/no)",
        "motivo de fallo si lo hay",
        "NSEC (NSEC/NSEC3/na)",
        "algoritmo",
        "keysize bits",
        "RRset firmadas",
        "DS en zona padre (sí/no)",
        "observaciones adicionales",
    ]

    print(f"Iniciando análisis de {len(DOMINIOS_A_ANALIZAR)} dominios configurados...")

    with open(nombre_csv, mode="w", newline="", encoding="utf-8") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=columnas)
        escritor.writeheader()

        for indice, dom in enumerate(DOMINIOS_A_ANALIZAR, 1):
            print(f"[{indice}/{len(DOMINIOS_A_ANALIZAR)}] Evaluando: {dom}...")
            resultado_fila = analizar_dominio(dom)
            escritor.writerow(resultado_fila)

    print(f"\n[+] ¡Éxito! Datos guardados correctamente en: {nombre_csv}")


if __name__ == "__main__":
    generar_reporte_csv()
