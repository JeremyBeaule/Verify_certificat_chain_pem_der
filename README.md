
## Introduction 🚀

La validation d'une chaîne de certificats X.509 est une étape cruciale dans la sécurisation des communications sur Internet. Les certificats X.509 sont utilisés dans de nombreux protocoles de sécurité, notamment TLS et SSL, qui sécurisent les communications entre les navigateurs web et les serveurs.

### Objectifs 🎯

- **Authenticité :** Confirmer l'authenticité du serveur ou du site web pour prévenir les attaques de type "homme du milieu".
  
- **Intégrité des données :** Assurer que les données échangées n'ont pas été altérées pendant le transfert.
  
- **Confidentialité :** Chiffrer les données en transit pour empêcher leur lecture par des tiers non autorisés.
  
- **Confiance des utilisateurs :** Renforcer la confiance des utilisateurs dans les sites web utilisant des certificats valides.
  
- **Exigences légales et de conformité :** Se conformer aux normes et réglementations en vigueur, telles que celles définies par l'industrie des cartes de paiement (PCI).

## Choix des outils, du langage et des librairies 🐍

Le projet a été réalisé en Python, un langage de programmation de haut niveau largement utilisé pour le développement de logiciels dans divers domaines.

### Modules utilisés 🔐

- **cryptography :** Pour la manipulation et la validation des certificats PEM ou DER.
  
- **ecdsa :** Pour effectuer une vérification mathématique de la signature du certificat.

## Étapes implémentées ⛓️

Toutes les étapes demandées ont été implémentées, permettant de traiter :

- Une chaîne ou un seul certificat
- La gestion des arguments de la ligne de commande
- La lecture du fichier de certificat
- L'extraction et la vérification de la clé publique
- L'affichage des informations du certificat sur une interface graphique
- La vérification de l'extension KeyUsage
- La vérification de la période de validité
- L'extraction et la vérification de l'algorithme de signature
- La validation récursive de la chaîne de certificats
- La vérification du statut de révocation avec CRL
- La vérification du statut de révocation avec OCSP

## Structure du programme 👨‍💻

Le programme est structuré en plusieurs fonctions qui effectuent des tâches spécifiques, facilitant ainsi la compréhension et la maintenance du code. Il utilise le module "argparse" pour gérer les arguments de la ligne de commande, permettant à l'utilisateur de spécifier le format du certificat et le chemin d'accès au fichier du certificat.

![Sans-titre-2024-03-25-1041](https://github.com/JeremyBeaule/Verify_certificat_chain_pem_der/assets/62985330/d93b2348-924f-4546-99b5-d0f02062788f)
![Sans-titre-2024-03-25-1041-2](https://github.com/JeremyBeaule/Verify_certificat_chain_pem_der/assets/62985330/cda14efb-8a33-4e7b-8605-b844c04b62d8)
![Sans-titre-2024-03-25-1041-4](https://github.com/JeremyBeaule/Verify_certificat_chain_pem_der/assets/62985330/49df720b-c4d7-4ce8-ad25-1b6d2394677d)
![Sans-titre-2024-03-25-1041-5](https://github.com/JeremyBeaule/Verify_certificat_chain_pem_der/assets/62985330/5ed23414-7812-4516-9e95-9ce499a7bef8)

<img width="732" alt="Capture d’écran 2024-03-30 à 18 27 30" src="https://github.com/JeremyBeaule/Verify_certificat_chain_pem_der/assets/62985330/080f8648-75db-4e09-9f40-56ff1b38360d">

## Difficultés rencontrées 💥

- **Calculs sur les courbes elliptiques :** La complexité des calculs mathématiques impliqués dans la vérification des signatures ECDSA a représenté un défi majeur, nécessitant une compréhension approfondie des principes cryptographiques sous-jacents.
  
- **Utilisation de la bibliothèque cryptography :** Malgré sa puissance, la prise en main de cette bibliothèque a exigé un effort significatif pour maîtriser ses différentes fonctionnalités et intégrer ses composants dans notre solution.

## Améliorations possibles 📈

- **Restructuration du code :** Pour améliorer la lisibilité et la maintenabilité du programme, une restructuration est envisageable.
  
- **Vérification des certificats par URL :** Ajouter une fonctionnalité permettant de valider les certificats d'un site directement par son URL renforcerait l'utilité du projet.
  
- **Historique des certificats traités :** La création d'un tableau Excel pour logger les certificats traités offrirait un suivi historique précieux.
  
- **Dockerisation :** Pour assurer une compatibilité multiplateforme, dockeriser l'application garantirait son exécution sur divers environnements.
  
- **Assistance utilisateur :** L'ajout d'un bouton d'information sur l'interface graphique, offrant des aides et des conseils, améliorerait l'expérience utilisateur.

## Ressources 📚

- **Aide au développement :** ChatGPT / Copilot
- **Librairie PEM parsing en Python :** [pem](https://github.com/hynek/pem?tab=readme-ov-file)
- **Documentation des librairies :**
  - [cryptography](https://cryptography.io/en/latest/x509/reference/)
  - [ecdsa](https://github.com/pyca/cryptography/tree/main)
- **Documentation complémentaire :** [Cryptographie](https://people.eecs.berkeley.edu/%7Ejonah/lcrypto/overview-summary.html)

## Concepteurs

- BEAULÉ Jeremy
- JAIL Jean-Baptiste
