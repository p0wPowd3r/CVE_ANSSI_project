from flask import Flask, render_template, request, redirect, url_for, flash
import smtplib
from email.mime.text import MIMEText
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.utils import PlotlyJSONEncoder

# Initialisation de l'application Flask
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Remplacez par une clé secrète sécurisée

CSV_FILE = "data_anssi.csv"
df = pd.read_csv(CSV_FILE)

# supprimer les doublons de ligne dans le DataFrame
df.drop_duplicates(inplace=True)

print (df)

# Chemin vers le fichier JSON pour stocker les abonnés
subscribers_file = os.path.join(app.static_folder, "subscribers.json")

def load_subscribers():
    """Charge la liste des abonnés depuis un fichier JSON."""
    if os.path.exists(subscribers_file):
        with open(subscribers_file, 'r') as f:
            return json.load(f)
    return []

def save_subscribers(subscribers):
    """Sauvegarde la liste des abonnés dans un fichier JSON."""
    with open(subscribers_file, 'w') as f:
        json.dump(subscribers, f)

def send_email(to_email, subject, template_name):
    """Envoie un email HTML via SMTP.

    Args:
        to_email (str): Adresse email du destinataire.
        subject (str): Sujet de l'email.
        template_name (str): Nom du template HTML à utiliser pour le corps de l'email.
    """
    from_email = "mailing.list.alert.anssi@gmail.com"
    password = "joja qpfn chdg oiqr"  # Mot de passe d'application sécurisé

    html_body = render_template(template_name, email=to_email)
    msg = MIMEText(html_body, 'html')
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")

def send_alert_email(subject, body):
    """Envoie un email d'alerte à tous les abonnés."""
    subscribers = load_subscribers()
    for email in subscribers:
        send_email(email, subject, body)

def generate_charts():
    """Génère des graphiques interactifs à partir des données et les encode en JSON."""
    charts = {}

    try:
        # Histogramme des scores CVSS
        fig_cvss = px.histogram(df, x="CVSS Score", nbins=10, title="Distribution des scores CVSS",
                                labels={"CVSS Score": "Score CVSS"}, template="plotly_white")
        charts['cvss_histogram'] = json.dumps(fig_cvss, cls=PlotlyJSONEncoder)

        # Diagramme circulaire des types de vulnérabilités (CWE)
        fig_cwe = px.pie(df, names="CWE", title="Répartition des types de vulnérabilités (CWE)")
        charts['cwe_pie'] = json.dumps(fig_cwe, cls=PlotlyJSONEncoder)

        # Courbe des scores EPSS
        fig_epss = px.line(df, x=df.index, y="EPSS", title="Courbe des scores EPSS",
                           labels={"x": "Index", "EPSS": "Score EPSS"}, template="plotly_white")
        charts['epss_line'] = json.dumps(fig_epss, cls=PlotlyJSONEncoder)

        # Classement des Produits impactéss les plus affectés
        product_counts = df['Produits impactés'].value_counts().head(10)
        fig_products = px.bar(product_counts, orientation="h", title="Produits impactéss les plus affectés",
                              labels={"index": "Produits impactés", "value": "Nombre de vulnérabilités"},
                              template="plotly_white")
        charts['products_bar'] = json.dumps(fig_products, cls=PlotlyJSONEncoder)

        # Heatmap des corrélations entre CVSS et EPSS
        corr_matrix = df[['CVSS Score', 'EPSS']].corr()
        fig_heatmap = go.Figure(data=go.Heatmap(
            z=corr_matrix.values,
            x=corr_matrix.columns,
            y=corr_matrix.index,
            colorscale="Viridis"
        ))
        fig_heatmap.update_layout(title="Corrélation entre CVSS et EPSS", template="plotly_white")
        charts['heatmap'] = json.dumps(fig_heatmap, cls=PlotlyJSONEncoder)

        # Nuage de points entre CVSS et EPSS
        fig_scatter = px.scatter(df, x="CVSS Score", y="EPSS", color="CVSS Severity", size="EPSS",
                                 title="Relation entre CVSS et EPSS",
                                 labels={"CVSS Score": "Score CVSS", "EPSS": "Score EPSS"},
                                 template="plotly_white")
        charts['scatter_plot'] = json.dumps(fig_scatter, cls=PlotlyJSONEncoder)

        # Boxplot des scores CVSS par Editeur
        fig_boxplot = px.box(df, x="Editeur", y="CVSS Score", title="Distribution des scores CVSS par Editeur",
                             labels={"Editeur": "Editeur", "CVSS Score": "Score CVSS"},
                             template="plotly_white")
        charts['boxplot'] = json.dumps(fig_boxplot, cls=PlotlyJSONEncoder)

        # Évolution temporelle des vulnérabilités détectées
        df['Date publication bulletin anssi'] = pd.to_datetime(df['Date publication bulletin anssi'])
        vuln_per_date = df.groupby('Date publication bulletin anssi').size().reset_index(name='Nombre de vulnérabilités')
        fig_time = px.line(vuln_per_date, x="Date publication bulletin anssi", y="Nombre de vulnérabilités",
                           title="Évolution temporelle des vulnérabilités détectées",
                           labels={"Date publication bulletin anssi": "Date publication bulletin anssi", "Nombre de vulnérabilités": "Nombre"},
                           template="plotly_white")
        charts['time_series'] = json.dumps(fig_time, cls=PlotlyJSONEncoder)

    except Exception as e:
        print(f"Erreur lors de la génération des graphiques : {e}")

    return charts

@app.route("/", methods=["GET", "POST"])
def home():
    """Page d'accueil pour la gestion des abonnés."""
    if request.method == "POST":
        email = request.form.get("email")
        if email and "@" in email:
            subscribers = load_subscribers()
            if email in subscribers:
                flash("Vous êtes déjà abonné(e) à notre liste.", "danger")
            else:
                subscribers.append(email)
                save_subscribers(subscribers)
                send_email(email, "Bienvenue à notre liste d'abonnement", "mail_bienvenue.html")
                flash("Merci pour votre abonnement. Vous recevrez des alertes par email.", "success")
        else:
            flash("Veuillez entrer une adresse email valide.", "danger")
        return redirect(url_for("home"))
    return render_template("index.html")

@app.route("/charts", methods=["GET"])
def charts():
    """Page pour afficher les graphiques générés."""
    charts = generate_charts()
    return render_template("charts.html", charts=charts)

if __name__ == "__main__":
    app.run(debug=True)
