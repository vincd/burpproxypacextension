MISC : Introduction au développement d'extensions Burp, Exemple Proxy PAC
=========================================================================

Description
-----------
Ce dépôt contient les sources et binaires mentionnés dans l'article MISC.
 * La librairie Java `Jython` permet d'utiliser un script écrit en Python comme extension de Burp.
 * Le script `proxy_pac.py` permet d'utiliser les fichiers de configuration de proxy PAC au sein de Burp.
 * La librarie `Proxy-vole` (https://code.google.com/p/proxy-vole/) permettant de lire un fichier PAC en Java.

Afin d'utiliser l'extension, il convient d'ajouter le chemin du dossier `jar` de ce repository dans le champ `Folder for loading modules (optional)` de l'onglet `Extender/Options` de Burp. Une fois l'extension lancée, l'onglet `Proxy PAC` permet d'ajouter le chemin du fichier PAC.

Copyright et licence
---------------------
Toutes les ressources de ce dépôt sont distribuées sous licence GPLv3.

Crédits
-------
* Vincent Dépériers
* Thomas Debize
