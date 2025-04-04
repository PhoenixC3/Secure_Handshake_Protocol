# TS_24_25 : PHASE 1 - "BUILD IT"

Grupo 04:
Tiago Almeida (58161)
Afonso Baptista (58213)
Rafael Correia (58256)

Como compilar e correr o projeto:
O projeto foi implementado em Java, utilizando o Maven. Apesar de já estar compilado e os ficheiros .jar já estarem na root folder seguem as instruções de como compilar e correr:

Compilar: Na root do projeto, efetuar:
    •	mvn clean install

Correr: Após os .jar estarem na root do projeto, efetuar os seguintes comandos (Comandos para os .jar que já estão presentes da nossa compilação e entregues, caso haja nova compilação, substituir nome do .jar pelo nome do artifacto gerado na root):
    •	Banco: java -jar Bank.jar -p <port> -s <auth-file>
        o	(A port e o auth file são argumentos opcionais, em caso de dúvida seguir as instruções do enunciado).
    •	ATM: java -jar ATM.jar -a <account>
        o	(O parâmetro account é obrigatório, para utilização dos restantes parâmetros seguir as instruções do enunciado).


Ps. Em caso de dúvida ou dificuldade ao correr contactar um dos seguintes emails:
    • fc58161@alunos.fc.ul.pt
    • fc58213@alunos.fc.ul.pt
    • fc58256@alunos.fc.ul.pt
