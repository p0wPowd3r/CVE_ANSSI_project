import feedparser
import requests
import re
import pandas as pd



#URL du flux RSS
url = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url)

#Initialisation d'une liste pour stocker les informations
rss_data = []

#Parcours des entrées du flux RSS
for entry in rss_feed.entries:
    # Création d'un dictionnaire pour chaque entrée
    rss_entry = {
        "Titre": entry.title, 
        "Description": entry.description,
        "Lien": entry.link,
        "Date": entry.published #pas besoin recuperer sur bulletin anssi
    }

    # Ajout du dictionnaire à la liste
    rss_data.append(rss_entry)

#Affichage du tableau (liste de dictionnaires)
#print(rss_data)

#Liste pour stocker tous les CVE trouvés dans chaque lien RSS
all_cve_list = []

#Liste pour stocker toutes les datas
all_data_cert_anssi = []

#Parcours des éléments dans rss_data
for entry in rss_data:
    # Construction de l'URL JSON en ajoutant '/json/' à l'URL de base
    json_url = entry["Lien"] + "/json/"

    try:
        # Requête HTTP pour récupérer les données JSON
        response = requests.get(json_url)
        response.raise_for_status()  # Vérifie si la requête a réussi

        # Chargement du contenu JSON
        data = response.json()

         # Extraire les informations désirées
        editeur = data["affected_systems"][0]["product"]["vendor"]["name"]  # Nom de l'éditeur
        date_publication = data["vendor_advisories"][0]["published_at"]  # Date de publication
        produits = [sys["product"]["name"] for sys in data["affected_systems"]]  # Liste des produits
        versions = [sys["description"] for sys in data["affected_systems"]]  # Liste des versions affectées
        type_b = data["reference"].split("-")[2]

        if type_b == "AVI" :
            type_bulletin = "Avis"
        else :
            type_bulletin = "Alerte"

        # Extraction des références CVE à partir de la clé "cves"
        ref_cves = list(data.get("cves", []))  # Assure-toi que "cves" existe dans la réponse

        # Extraction des CVE via une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))  # Extraction des CVE

        # Ajout des CVE extraits à la liste globale
        all_cve_list.extend(cve_list)

        data_cert_anssi = {
            "CVE du bulletin" : cve_list,
            "Editeur" : editeur,
            "Date publication bulletin anssi" : date_publication,
            "Produits impactés" : produits,
            "Versions concernés" : versions,
            "Type du bulletin" : type_bulletin,
        }

        all_data_cert_anssi.append(data_cert_anssi)

        # Affichage des informations de l'alerte et des CVE
        #print(f"Alerte: {entry['Titre']}")
        #print("CVE trouvés :", cve_list)

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des données pour l'alerte {entry['Titre']} : {e}")

#Affichage de tous les CVE extraits
#print("\nTous les CVE extraits depuis les flux RSS:")
#for data in all_data_cert_anssi:
    #print(data)


cve_data = [] # créer une liste pour stocker les inofs des cve

# Fonction pour récupérer les informations d'un CVE via l'API
def get_cve_info(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    uvl = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=1, verify=True)
        response.raise_for_status()  # Vérifie si la requête a réussi
        data = response.json()

        responsevl = requests.get(uvl, timeout=1, verify=True)
        responsevl.raise_for_status()  # Vérifie si la requête a réussi
        datavl = responsevl.json()

        # Extraire la description
        description = "Non disponible"
        if "containers" in data and "cna" in data["containers"]:
            cna = data["containers"]["cna"]
            if "descriptions" in cna and len(cna["descriptions"]) > 0:
                description = cna["descriptions"][0].get("value", "Non disponible")


        # Extraire le score CVSS
        cvss_score = "Non disponible"
        try:
            containers = data.get("containers", {})
            if containers:
                cna = containers.get("cna", {})
                if cna and "metrics" in cna:
                    metrics = cna["metrics"]
                    if metrics:
                        # Vérification de la présence de cvssV3_1 ou cvssV3_0
                        if "cvssV3_1" in metrics[0]:
                            cvss_score = cna["metrics"][0]["cvssV3_1"]["baseScore"]
                        elif "cvssV3_0" in metrics[0]:
                            cvss_score = cna["metrics"][0]["cvssV3_0"]["baseScore"]
        except (IndexError, KeyError):
            cvss_score = "Non disponible"

        if cvss_score != "Non disponible" :
            cvss_ent = int(cvss_score)
            cvss_float = float(cvss_ent)
            try :
              if cvss_float == 0 :
                  cvss_severity = "None"
              elif 0.01 <= cvss_float <= 3.99:
                cvss_severity = "Low"
              elif 4.0 <= cvss_float <= 6.99:
                cvss_severity = "Medium"
              elif 7.0 <= cvss_float <= 8.99:
                cvss_severity = "High"
              elif cvss_float >= 9.0:
                cvss_severity = "Critical"
            except :
              cvss_severity = "Non dsiponible"
        else : cvss_severity = "Non disponible"
  

        # Extraire le CWE et sa description
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Extraire le score EPSS
        epss_data = datavl.get("data", [])
        if epss_data:
            epss_score = epss_data[0]["epss"]
            #print(f"CVE : {cve_id}")
            #print(f"Score EPSS : {epss_score}")
        else:
            epss_score = "Non disponible"

        # Ajouter les données du CVE à la liste
        cve_info = {
            "CVE": cve_id,
            "Description": description,
            "CVSS Score": cvss_score,
            "CVSS Severity": cvss_severity,
            "CWE": cwe,
            "CWE Description": cwe_desc,
            "EPSS" : epss_score
        }

        return cve_info

    except requests.exceptions.Timeout:
        print(f"Erreur de délai d'attente pour le CVE {cve_id}. La requête a été annulée après 10 secondes.")
        return None

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des informations pour le CVE {cve_id} : {e}")
        return None

# Récupérer les informations pour chaque CVE dans la liste
for cve in all_cve_list:
    cve_info = get_cve_info(cve)
    if cve_info:
        cve_data.append(cve_info)


# Affichage des données des CVE
#print("\nDonnées des CVE extraites :")
#for data in cve_data:
    #print(data)



# Initialisation d'une liste pour stocker les données pour chaque ligne
rows = []

# Parcours des éléments dans rss_data et all_data_cert_anssi
for entry, cert_data in zip(rss_data, all_data_cert_anssi):
    # Informations de base du flux RSS
    titre = entry["Titre"]
    lien = entry["Lien"]
    description = entry["Description"]

    # Informations du certificat (type, date, éditeur, produits, versions, cve)
    type_bulletin = cert_data["Type du bulletin"]
    date_publication = cert_data["Date publication bulletin anssi"]
    editeur = cert_data["Editeur"]
    produits = ", ".join(cert_data["Produits impactés"])
    versions = ", ".join(cert_data["Versions concernés"])
    cve_list = ", ".join(cert_data["CVE du bulletin"])

    # Parcours des CVE pour récupérer les informations détaillées
    for cve in cert_data["CVE du bulletin"]:
        # Récupérer les informations détaillées pour chaque CVE
        cve_info = get_cve_info(cve)

        if cve_info:
            # Informations détaillées pour chaque CVE
            cwe = cve_info.get("CWE", "Non disponible")
            cwe_desc = cve_info.get("CWE Description", "Non disponible")
            cvss_score = cve_info.get("CVSS Score", "Non disponible")
            cvss_severity = cve_info.get("CVSS Severity", "Non disponible")
            epss_score = cve_info.get("EPSS", "Non disponible")
            
            # Ajouter les données sous forme de ligne pour chaque CVE
            row = {
                "Titre": titre,
                "Lien": lien,
                "Description": description,
                "Type du bulletin": type_bulletin,
                "Date publication bulletin anssi": date_publication,
                "Editeur": editeur,
                "Produits impactés": produits,
                "Versions concernés": versions,
                "CVE du bulletin": cve_list,
                "CVE": cve,  # Ajout du CVE précis dans la ligne
                "CWE": cwe,
                "CWE Description": cwe_desc,
                "CVSS Score": cvss_score,
                "CVSS Severity": cvss_severity,
                "EPSS": epss_score
            }

            # Ajouter la ligne au DataFrame
            rows.append(row)

# Créer un DataFrame avec toutes les données
df = pd.DataFrame(rows)

# enregistrement des données dans un fichier CSV le dataframe
df.to_csv("cert_anssi_data_2.csv", index=False)
# Affichage du DataFrame
print(df)