# TS_24_25

To test the program do the following:

Open a terminal and navigate to the folder where the .java are located
Execute "javac BankServer.java ATMClient.java"
Start the bank server in that terminal with the command "java BankServer -p <port> -s <auth-file name>"
    (example: java BankServer -p 3000 -s bank.auth)
    (the bank.auth file can not exist already)
Open another terminal
Execute the ATM client with the following possible commands:
    - Create an account: java ATMClient -s bank.auth -a <account> -c <card-file> -n <balance>
    (example: java ATMClient -s bank.auth -a bob -c bob.card -n 1000.00)
    - Deposit money: java ATMClient -s bank.auth -a <account> -c <card-file> -d <amount>
    (example: java ATMClient -s bank.auth -a bob -c bob.card -d 200.00)
    - Withdraw money: java ATMClient -s bank.auth -a <account> -c <card-file> -w <amount>
    (example: java ATMClient -s bank.auth -a bob -c bob.card -w 150.00)
    - Check balance: java ATMClient -s bank.auth -a <account> -c <card-file> -g
    (example: java ATMClient -s bank.auth -a bob -c bob.card -g)
