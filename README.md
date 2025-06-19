# 🛡️ VulnHunter - Professional Vulnerability Scanner

VulnHunter est un outil complet de scanning de vulnérabilités qui combine :
- Scan de ports et services
- Détection de vulnérabilités CVE
- Tests de sécurité web
- Rapports détaillés
- Interfaces CLI et Web

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)

## ✨ Fonctionnalités

- **Scan réseau avancé**
  - Détection des ports ouverts
  - Identification des services et versions
  - Récupération des bannières

- **Recherche de vulnérabilités**
  - Intégration avec CIRCL et NVD
  - Scores CVSS prioritaires
  - Recherche multi-sources

- **Scan web**
  - Tests XSS, SQLi, CORS
  - Détection de technologies vulnérables
  - Classement par sévérité

- **Rapports professionnels**
  - Formats texte et JSON
  - Horodatage automatique
  - Structure hiérarchique

- **Interfaces multiples**
  - CLI conviviale
  - Interface web moderne
  - API RESTful

## 🚀 Installation

1. **Prérequis** :
   - Python 3.8+
   - Nmap installé

2. **Clonage du dépôt** :
  ```bash
  git clone https://github.com/votre_user/VulnHunter.git
  cd VulnHunter
  ```

3. **Installation des dépendances** :
  ```bash
  pip install -r requirements.txt
  ```

4. **Configuration (optionnel)** :

- Créer un fichier ```.env``` pour la clé API NVD :
  ```bash
  NVD_API_KEY=votre_cle_api
  ```

## 🖥️ Utilisation

### Mode CLI

  ```bash
  python main.py
  ```

**Suivez les invites pour entrer** :

  1. Cible (IP ou nom de domaine)
  2. Plage de ports (par défaut : 1-1000)
  3. Activation du scan web

### Mode Web

**Décommentez la ligne suivante dans ```main.py```** :
  ```bash
  app.run(host='0.0.0.0', port=5000, threaded=True)
  ```

**Puis lancez** :
  ```bash
  python main.py
  ```

**Accédez à : http://localhost:5000**

## ⚠️ Avertissements et Éthique

  - **Autorisation obligatoire** : Ne scannez jamais des systèmes sans autorisation écrite
  - **Usage légal uniquement** : Cet outil est destiné à des tests de sécurité éthiques
  - **Risques de faux positifs** : Les résultats doivent toujours être validés manuellement
  - **Impact système** : Les scans agressifs peuvent perturber les services

## 📜 Licence
MIT License - Voir le fichier [LICENSE](LICENSE)

## 👥 Contribution

**Les contributions sont bienvenues ! Workflow recommandé** :
  1. Fork du projet
  2. Création d'une branche (```feature/ma-fonctionnalité```)
  3. Commit des changements
  4. Push vers la branche
  5. Ouverture d'une Pull Request

