import feedparser
import requests
import re
import time
import pandas as pd
import threading
import os

# Chemin du fichier CSV
CSV_FILE = "data_anssi.csv"

# Charger le fichier CSV ou initialiser un DataFrame vide
if os.path.exists(CSV_FILE):
    df = pd.read_csv(CSV_FILE)
else:
    df = pd.DataFrame(columns=[
        "Titre", "Lien", "Description", "Type du bulletin", "Date publication bulletin anssi",
        "Editeur", "Produits impactés", "Versions concernés", "CVE", "CWE",
        "CWE Description", "CVSS Score", "CVSS Severity", "EPSS"
    ])

# Fonction pour récupérer les informations d'un CVE via l'API
def get_cve_info(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    uvl = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=10, verify=True)
        response.raise_for_status()
        data = response.json()

        responsevl = requests.get(uvl, timeout=10, verify=True)
        responsevl.raise_for_status()
        datavl = responsevl.json()

        description = "Non disponible"
        if "containers" in data and "cna" in data["containers"]:
            cna = data["containers"]["cna"]
            if "descriptions" in cna and len(cna["descriptions"]) > 0:
                description = cna["descriptions"][0].get("value", "Non disponible")

        cvss_score = "Non disponible"
        cvss_severity = "Non disponible"
        try:
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
            if metrics:
                if "cvssV3_1" in metrics[0]:
                    cvss_score = metrics[0]["cvssV3_1"]["baseScore"]
                elif "cvssV3_0" in metrics[0]:
                    cvss_score = metrics[0]["cvssV3_0"]["baseScore"]
            
                if cvss_score != "Non disponible":
                    cvss_score = float(cvss_score)
                    if cvss_score == 0:
                        cvss_severity = "None"
                    elif 0.01 <= cvss_score <= 3.99:
                        cvss_severity = "Low"
                    elif 4.0 <= cvss_score <= 6.99:
                        cvss_severity = "Medium"
                    elif 7.0 <= cvss_score <= 8.99:
                        cvss_severity = "High"
                    elif cvss_score >= 9.0:
                        cvss_severity = "Critical"
        except (IndexError, KeyError):
            pass

        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        epss_score = "Non disponible"
        epss_data = datavl.get("data", [])
        if epss_data:
            epss_score = epss_data[0].get("epss", "Non disponible")

        return {
            "CVE": cve_id,
            "Description": description,
            "CVSS Score": cvss_score,
            "CVSS Severity": cvss_severity,
            "CWE": cwe,
            "CWE Description": cwe_desc,
            "EPSS": epss_score
        }

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des informations pour le CVE {cve_id} : {e}")
        return None

# Fonction principale pour surveiller les flux RSS
def monitor_rss():
    global df
    url_avis = "https://www.cert.ssi.gouv.fr/avis/feed"
    url_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed"

    while True:
        for feed_url in [url_avis, url_alerte]:
            rss_feed = feedparser.parse(feed_url)
            for entry in rss_feed.entries:
                if entry.link not in df["Lien"].values:
                    print(f"Nouvelle entrée détectée : {entry.title}")
                    
                    json_url = entry.link + "/json/"
                    try:
                        response = requests.get(json_url)
                        response.raise_for_status()
                        data = response.json()

                        editeur = "Non disponible"
                        if data.get("affected_systems"):
                            editeur = data["affected_systems"][0]["product"]["vendor"]["name"]

                        date_publication = "Non disponible"
                        if data.get("vendor_advisories"):
                            date_publication = data["vendor_advisories"][0]["published_at"]

                        produits = [sys["product"]["name"] for sys in data.get("affected_systems", [])]
                        versions = [sys.get("description", "") for sys in data.get("affected_systems", [])]

                        type_b = data["reference"].split("-")[2]
                        type_bulletin = "Avis" if type_b == "AVI" else "Alerte"

                        cve_list = list(set(re.findall(r"CVE-\\d{4}-\\d{4,7}", str(data))))
                        
                        for cve in cve_list:
                            cve_info = get_cve_info(cve)
                            if cve_info:
                                row = {
                                    "Titre": entry.title,
                                    "Lien": entry.link,
                                    "Description": entry.description,
                                    "Type du bulletin": type_bulletin,
                                    "Date publication bulletin anssi": date_publication,
                                    "Editeur": editeur,
                                    "Produits impactés": ", ".join(produits),
                                    "Versions concernés": ", ".join(versions),
                                    "CVE": cve_info["CVE"],
                                    "CWE": cve_info["CWE"],
                                    "CWE Description": cve_info["CWE Description"],
                                    "CVSS Score": cve_info["CVSS Score"],
                                    "CVSS Severity": cve_info["CVSS Severity"],
                                    "EPSS": cve_info["EPSS"]
                                }
                                df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
                                df.to_csv(CSV_FILE, index=False)
                    except requests.exceptions.RequestException as e:
                        print(f"Erreur lors de la récupération des données pour le lien {entry.link} : {e}")
        time.sleep(60)

# Démarrage du thread
thread = threading.Thread(target=monitor_rss, daemon=True)
thread.start()

print("Surveillance des flux RSS démarrée...")

# Maintenir le programme principal en cours d'exécution
try:
    while True:
        time.sleep(1)  # Attente pour éviter une boucle qui consomme des ressources
except KeyboardInterrupt:
    print("\nArrêt de la surveillance des flux RSS.")
