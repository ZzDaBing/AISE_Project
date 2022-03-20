# AISE debugger

## Principe

Ce programme permet d'exécuter un fichier ELF donné en argument et de récupérer des informations sur sa structure
ainsi que le signal de retour si ce programme rencontre une erreur afin de pouvoir identifier le problème.
Lors de la compilation du programme, un dossier info_dir est créé. Lors de l'exécution, ce dossier récupèrera différents
fichiers contenant les informations que l'on trouve dans /proc/(child)/maps et /proc/(child)/status, (child) étant le
processus qui lancera l'exécutable à tracer. Le tracer (father) communique avec le tracee (child) grâce à la fonction ptrace().

## Fonctionnement

Compile le debugger :
```
make
```

Exécute le debugger pour un exécutable à debugger :
```
./debug <executable>
```

Nettoie tous les fichiers issus du Makefile:
```
make clean
```

## Résultats

Notre debugger implémente différentes fonctionnalités résumées plus haut. Dans le détail, grâce à la librairie ptrace(),
nous pouvons afficher le signal levé à la fin de l'exécution de l'exécutable à debugger ainsi que son code pour certains
de ces signaux (cf mysiginfo.c). Par exemple pour un SIGSEGV, on peut savoir quel type de faute de segmentation dont
il est question. Ensuite, nous pouvons afficher la valeur des différents registres du processeur. La fonction print_allregs()
et print_mainregs() affichent respectivement tous les registres ou les principaux. Les autres fonctions servent à récupérer
les fichiers /proc/(child)/maps et /proc/(child)/status comme expliqué plus haut. Enfin, dans le père, on peut faire évoluer
l'exécution du child instructions par instructions ou syscall par syscall. Pour ces derniers, le fichier mysyscall.c permet
d'identifier quel syscall est appelé à chaque appel de syscall indiqué dans le registre orig_rax.
Une partie du code utilise la structure du ELF et affiche certaines informations comme le Program Header, la Section Header
ou encore la table des symboles.

## Non réalisé

Nous aurions aimé créer plus de fonctionnalités pour notre debugger mais diverses raisons ont fait que cela ne fut pas
possible. En effet, une interface "à la GDB" aurait été appréciable, mais pas possible de le réaliser dans les temps.
On a voulu utiliser les adresses issues de /proc/(child)/maps mais nous n'avons pas réussi à convertir avec les adresses
statiques du header de l'exécutable. On obtenait bien des adresses grâce au registre rip (instruction pointer) et à PTRACE_PEEKTEXT mais ce manque de conversion entre les adresses nous faisait obtenir des codes d'opérations qui
ne corespondaient pas. Pourtant on avait préparé grâce à la librairie Capstone de quoi convertir en code assembleur.
Comme dit dans la partie résultats, nous utilisons la structure du ELF pour récupérer certaines informations que nous affichons
par la suite. Néanmoins nous n'avons pas réussi à récupérer toutes les informations que l'on aurait voulu, comme récolter le contenu
de la section <.text> ou <.data>, qui auraient été très utiles.
Aussi, un system objdump est appelé pour afficher des informations très utiles pour le déboggage. Comme future mise à jour,
une possibilité seerait d'améliorer ce point en affichant les mêmes infos sans passer par l'appel à objdump.
Nous n'avons pas exploré le dwarf car assez compliqué à comprendre et étions sur des pistes différentes que celle-là, mais
ca peut être une amélioration fructueuse dans le programme.
