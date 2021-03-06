MISC 82 Introduction au développement d'extensions Burp - Exemple Proxy PAC
==================================================================================

**English speakers, please read the [translated README](https://github.com/vincd/burpproxypacextension/wiki/English-README-for-the-Burp-Proxy-Extension) page**

Description
-----------
Ce dépôt contient les sources et binaires de l'extension `Proxy PAC` décrite dans l'article `Introduction au développement d'extensions Burp` du MISC n°82.  
Les ressources sont regroupées ainsi :
```
+---proxy_pac.py			: Le code Jython de l'extension
|
+---proxy-vole_20131209.jar	: La bibliothèque Proxy-vole
```


Configuration et utilisation
------------------------------
0. Sélectionner le **chemin vers l'interpréteur Jython** au sein de Burp  

1. Sélectionner un dossier dans le champ `Folder for loading modules (optional)` de l'onglet `Extender/Options` de Burp  

2. Ajouter le **fichier JAR de la bibliothèque `Proxy-vole` dans le dossier sélectionné précédemment**, il sera automatiquement pris en compte par l'extension    

3. Charger l'extension `proxy_pac.py` au sein de l'onglet `Extender` : **un onglet `Proxy PAC` apparait au sein des onglets de Burp**  

4. Dans l’onglet `Proxy PAC` nouvellement créé, placer l’URL du fichier proxy PAC, changer au besoin l'interface (localhost par défaut) et le port d'écoute (9090 par défaut) puis cliquer sur `Start Proxy PAC`  
 La **bonne prise en compte des paramètres** est affichée dans l'onglet Burp `Alerts`  
 
5. Dans l'onglet Burp `Proxy`, ajouter un `Upstream Proxy Server` avec les paramètres suivants, à adapter vis-à-vis des paramètres choisis à l'étape précédente :
    ```
    Destination host: *
    Proxy host: 127.0.0.1
    Proxy port: 9090
    ```

6. Configurer le navigateur pour rediriger les flux vers le **proxy Burp** (celui configuré dans l'onglet Burp `Proxy` et **non celui configuré dans l'onglet de l'extension**)

7. Les **traces de prise en compte** du fichier `proxy.pac` apparaissent dans l'onglet de l'extension `Proxy PAC`


Dépendances
-----------
* La bibliothèque `Jython`, téléchargeable [ici](http://search.maven.org/remotecontent?filepath=org/python/jython-standalone/2.7.0/jython-standalone-2.7.0.jar)
* La bibliothèque `Proxy-vole`, incluse dans ce dépôt et téléchargeable [ici](https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/proxy-vole/proxy-vole_20131209_bin.zip), qui assure l'interprétation du fichier .PAC


Copyright et licence
---------------------
Toutes les ressources de ce dépôt sont distribuées sous licence GPLv3.


Crédits
-------
* Vincent Dépériers
* Thomas Debize
