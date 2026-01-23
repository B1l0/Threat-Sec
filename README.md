# ThreatIntel Aggregator

Un outil open-source d'agrégation, de validation et de gestion de listes de blocage (Blocklists) pour la cybersécurité.

Ce projet collecte des indicateurs de compromission (IOCs) depuis des sources publiques, permet des contributions communautaires manuelles, et valide les données via des APIs de sécurité (VirusTotal, AbuseIPDB) avant de générer une liste consolidée.

## 🚀 Fonctionnalités

*   **Multi-sources** : Agrégation automatique de feeds publics (URLHaus, OpenPhish).
*   **Validation Intelligente** : Vérification des ajouts manuels via VirusTotal et AbuseIPDB pour éviter les faux positifs.
*   **Gestion Communautaire** : Support simple pour ajouter (`add_requests.txt`) ou retirer (`remove_requests.txt`) des domaines.
*   **Whitelist Stricte** : Protection intégrée des domaines légitimes majeurs (Google, Microsoft, etc.).
*   **Automation** : Workflow GitHub Actions pour une mise à jour quotidienne automatique.
*   **Configuration Facile** : Assistant de configuration en ligne de commande.

## 📋 Prérequis

*   Python 3.10 ou supérieur.
*   Un compte GitHub (pour le fork et l'automation).
*   Clés API (optionnelles mais recommandées) pour VirusTotal et AbuseIPDB.

## 🛠️ Installation

1.  **Cloner le dépôt :**
    ```bash
    git clone https://github.com/votre-utilisateur/threat-intel-aggregator.git
    cd threat-intel-aggregator
    ```

2.  **Installer les dépendances :**
    ```bash
    pip install -r requirements.txt
    ```

## ⚙️ Configuration

Utilisez l'assistant de configuration intégré pour configurer vos clés API. Le script vous proposera également une liste de services gratuits recommandés.

```bash
python main.py --conf
```

Cela créera un fichier `.env` contenant vos secrets.
*Note : Si vous utilisez GitHub Actions, n'oubliez pas d'ajouter ces mêmes clés dans les "Secrets" de votre dépôt GitHub (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`).*

## ▶️ Utilisation

### Lancer l'agrégation manuellement

Pour lancer le processus complet (récupération, validation, consolidation) :

```bash
python main.py
```

Le résultat sera généré dans le fichier : `bad_motherfuckerz.txt`.

### Gestion des Listes (Input)

Vous pouvez influencer la liste finale en modifiant les fichiers dans le dossier `input/` :

*   **Ajouter un domaine suspect :**
    Ajoutez le domaine ou l'IP dans `input/add_requests.txt` (un par ligne).
    *Le script tentera de le valider via les APIs configurées avant de l'inclure.*

*   **Retirer un faux positif :**
    Ajoutez le domaine ou l'IP dans `input/remove_requests.txt`.
    *Ces entrées seront retirées de la liste finale, quelle que soit leur source.*

*   **Whitelist permanente :**
    Le fichier `whitelist.txt` contient les domaines qui ne doivent **jamais** être bloqués.

## 🏗️ Architecture

*   `sources/` : Modules de récupération des feeds publics.
*   `core/` : Logique de normalisation, déduplication et application des règles (Whitelist/Blacklist).
*   `integrations/` : Clients API pour VirusTotal et AbuseIPDB (avec gestion des quotas).
*   `utils/` : Gestion des fichiers, logs et menus.
*   `.github/workflows/` : Configuration CI/CD pour l'exécution quotidienne.

## 🤖 Automatisation (GitHub Actions)

Le projet inclut un workflow (`update_blocklist.yml`) qui :
1.  S'exécute tous les jours à minuit.
2.  Récupère les dernières menaces.
3.  Met à jour le fichier `bad_motherfuckerz.txt`.
4.  Commit et Push les changements directement sur le dépôt.

## 🤝 Contribuer

Les contributions sont les bienvenues ! Pour proposer un changement de code ou une amélioration de la whitelist, n'hésitez pas à ouvrir une Pull Request.

## 📄 Licence

Ce projet est distribué sous licence MIT.
