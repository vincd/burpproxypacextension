MISC 82 Introduction au développement d'extensions Burp - Exemple Proxy PAC
==================================================================================

Description
-----------
Ce dépôt contient les sources et binaires de l'extension "Proxy PAC" décrite dans l'article `Introduction au développement d'extensions Burp` du MISC n°82.  
Les ressources sont regroupées ainsi :
```
+---proxy_pac.py			: Le code Jython de l'extension
|
+---proxy-vole_20131209.jar	: La bibliothèque Proxy-vole
```


Usage
-----
0. Sélectionner le chemin vers l'interpréteur Jython au sein de Burp ; 
1. Sélectionner un dossier dans le champ `Folder for loading modules (optional)` de l'onglet `Extender/Options` de Burp ;
2. Ajouter le fichier JAR de la bibliothèques Proxy-vole dans le dossier sélectionné précédemment ;
3. Charger l'extension `proxy_pac.py` au sein de l'onglet `Extender` : un onglet `Proxy PAC` apparait au sein des onglets de Burp.


Dépendances
-----------
* La bibliothèque `Jython`, téléchargeable [ici](http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar)
* La bibliothèque `Proxy-vole`, incluse dans ce dépôt et téléchargeable [ici](https://code.google.com/p/proxy-vole), qui assure l'interprétation du fichier .PAC


Copyright et licence
---------------------
Toutes les ressources de ce dépôt sont distribuées sous licence GPLv3.


Crédits
-------
* Vincent Dépériers
* Thomas Debize
