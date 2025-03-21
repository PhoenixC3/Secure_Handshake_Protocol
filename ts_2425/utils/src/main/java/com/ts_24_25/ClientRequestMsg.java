package com.ts_24_25;

import java.io.Serializable;

public class ClientRequestMsg implements Serializable {

    private CommandType cmdType;
	private String account;
	private String cardFile;
	private String amount;

    public ClientRequestMsg(CommandType cmdType, String account, String cardFile, String amount) {
		this.cmdType = cmdType;
		this.account = account;
		this.cardFile = cardFile;
		this.amount = amount;
	}

    public CommandType getCmdType() {
        return cmdType;
    }

    public String getAccount() {
        return account;
    }

    public String getCardFile() {
        return cardFile;
    }

    public String getAmount() {
        return amount;
    }

    public void setCmdType(CommandType cmdType) {
        this.cmdType = cmdType;
    }

    public void setAccount(String account) {
        this.account = account;
    }

    public void setCardFile(String cardFile) {
        this.cardFile = cardFile;
    }

    public void setAmount(String amount) {
        this.amount = amount;
    } 
}
