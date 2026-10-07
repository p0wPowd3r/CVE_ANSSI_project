# Projet ANSSI — Surveillance des vulnérabilités

## Description du projet

Ce projet Python vise à surveiller en continu les flux RSS d'avis et d'alertes publiés par l'**Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI)**.

Les vulnérabilités détectées sont enrichies à l'aide d'API externes, consolidées dans un fichier CSV, puis analysées afin de produire des graphiques interactifs.

Les utilisateurs peuvent également s'abonner pour recevoir des **alertes personnalisées par e-mail** lorsque de nouvelles vulnérabilités sont détectées.

---

## Fonctionnalités principales

1. **Extraction des données ANSSI**

   * Surveillance des flux RSS de l'ANSSI.
   * Détection automatique des nouvelles vulnérabilités.

2. **Enrichissement des vulnérabilités (CVE)**

   * Utilisation de l'API CVE de **MITRE** pour récupérer :

     * les descriptions ;
     * les scores CVSS ;
     * les types CWE.
   * Utilisation de l'API **EPSS** pour évaluer la probabilité d'exploitation d'une vulnérabilité.

3. **Consolidation des données**

   * Stockage des informations dans un fichier CSV.
   * Manipulation et traitement des données avec **Pandas**.

4. **Visualisation interactive**

   * Génération de graphiques interactifs avec **Plotly**.
   * Analyse des vulnérabilités selon différents critères.

5. **Alertes et notifications par e-mail**

   * Gestion d'une liste d'abonnés.
   * Envoi automatique d'e-mails lors de la détection de nouvelles vulnérabilités critiques.

---

## Installation

### Prérequis

* Python **3.8 ou supérieur**.
* Git.

### Installation des bibliothèques

Installez les dépendances nécessaires avec :

```bash
pip install flask pandas feedparser requests plotly
```

> **Remarque :** `smtplib` fait partie de la bibliothèque standard de Python et ne nécessite donc pas d'installation avec `pip`.

### Configuration de Gmail

L'application utilise un compte Gmail pour envoyer les alertes par e-mail.

Un compte dédié a été créé pour le projet.

Pour l'envoi d'e-mails, il est nécessaire de configurer un **mot de passe d'application Google**.

---

## Cloner le dépôt

Clonez le projet avec :

```bash
git clone https://github.com/badmiaou/CVE_ANSSI_project.git
```

Puis placez-vous dans le dossier du projet :

```bash
cd CVE_ANSSI_project/src/webb_app
```

---

## Structure du projet

```text
CVE_ANSSI_project/
│
├── src/
│   └── webb_app/
│       ├── app.py                         # Code principal de l'application Flask
│       │
│       ├── static/
│       │   └── subscribers.json           # Liste des abonnés
│       │
│       ├── database/
│       │   └── data_anssi.csv             # Données des vulnérabilités
│       │
│       ├── templates/
│       │   ├── index.html                 # Page d'accueil
│       │   ├── charts.html                # Page des graphiques
│       │   └── mail_vulnerability.html    # Modèle des alertes e-mail
│       │
│       └── README.md                      # Documentation du projet
```

---

## Utilisation

### Lancer l'application

Depuis le dossier `webb_app`, exécutez :

```bash
python3 app.py
```

L'application sera alors accessible à l'adresse :

```text
http://127.0.0.1:5002
```

### Fonctionnalités web

L'application propose notamment :

* **Page d'accueil**

  * Présentation du projet.
  * Inscription à la liste de diffusion.
  * Gestion des abonnements aux alertes.

* **Page des graphiques**

  * Visualisation des vulnérabilités.
  * Analyse des scores CVSS et EPSS.
  * Analyse des types de vulnérabilités.

### Gestion des flux RSS

L'application surveille automatiquement les flux RSS de l'ANSSI toutes les **60 secondes**.

Lorsqu'une nouvelle vulnérabilité est détectée :

1. Les informations sont récupérées depuis le flux RSS.
2. La vulnérabilité est enrichie avec les données des API externes.
3. Les informations sont enregistrées dans le fichier CSV.
4. Une alerte peut être envoyée aux abonnés concernés.

---

## Points importants

### Gestion des ressources externes

Afin de limiter les requêtes vers les services externes :

* des délais entre les requêtes (**Rate Limiting**) sont implémentés ;
* les interactions avec les API sont limitées ;
* les flux RSS et les réponses JSON peuvent être pré-téléchargés afin de réduire le nombre de requêtes externes.

### Sécurité

Les informations sensibles doivent rester confidentielles.

**Ne jamais publier dans GitHub :**

* les identifiants Gmail ;
* les mots de passe ;
* les mots de passe d'application ;
* les clés API ;
* les fichiers contenant des informations sensibles.

Il est recommandé d'utiliser des **variables d'environnement** pour stocker les informations sensibles.

---

## Visualisations générées

L'application permet de générer plusieurs types de graphiques interactifs avec **Plotly**.

### Score CVSS

Histogrammes permettant d'analyser la répartition des scores de criticité des vulnérabilités.

### Types CWE

Diagrammes permettant de visualiser la répartition des différents types de vulnérabilités (**CWE**).

### CVSS vs EPSS

Nuages de points permettant d'étudier la relation entre :

* le score **CVSS**, représentant la sévérité d'une vulnérabilité ;
* le score **EPSS**, représentant la probabilité d'exploitation.

### Produits et éditeurs

Classements permettant d'identifier :

* les produits les plus affectés ;
* les éditeurs les plus affectés.

---

## Technologies utilisées

| Technologie       | Utilisation                 |
| ----------------- | --------------------------- |
| **Python**        | Langage principal           |
| **Flask**         | Application web             |
| **Pandas**        | Traitement des données      |
| **Feedparser**    | Lecture des flux RSS        |
| **Requests**      | Requêtes HTTP vers les API  |
| **Plotly**        | Visualisations interactives |
| **MITRE CVE API** | Informations sur les CVE    |
| **EPSS API**      | Probabilité d'exploitation  |
| **ANSSI RSS**     | Sources des alertes et avis |

---

## Auteurs

Projet réalisé par Brahami Maryam, Louis Escudié, Antoine Sechelige, dans le cadre du cours de **programmation Python** à l'ESILV (2024).
