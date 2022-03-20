Ce programme permet d'exécuter un fichier ELF donné en argument et de
récupérer des informations sur sa structure ainsi que le signal de retour
si ce programme rencontre une erreur afin de pouvoir identifier le problème.
Lors de la compilation du programme, un dossier info_dir est créé.
Lors de l'exécution, ce dossier récupèrera différents fichiers contenant
les informations que l'on trouve dans /proc/(child)/maps et /proc/(child)/status,
(child) étant le processus qui lancera l'exécutable à tracer.
Le tracer communique avec le tracee grâce à la fonction ptrace().

Compile program:
`make`

Run program:
`./debug <executable>`

Clean:
`make clean`
