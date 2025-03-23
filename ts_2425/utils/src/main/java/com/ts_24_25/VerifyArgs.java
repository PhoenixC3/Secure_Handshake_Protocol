package com.ts_24_25;

public class VerifyArgs {
    public static boolean verifyPort(String port) {
		if (port == null || port.isEmpty()) {
			return false;
		}
		port = port.trim();
		int portNumber;
		try {
			portNumber = Integer.parseInt(port);
		} catch (NumberFormatException e) {
			return false;
		}
	
		if (port.startsWith("0") && port.length() > 1) {
			return false;
		}
	
		return portNumber >= 1024 && portNumber <= 65535;
	}
	
	public static boolean verifyFileNames(String fileName) {
		if (fileName.length() < 1 || fileName.length() > 127 || fileName.equals(".") || fileName.equals("..")) 
			return false; 
		
		for(String c : fileName.split("")) {
			if (!c.matches("[_\\-\\.0-9a-z]")) 
				return false;
		}
		return true;
	}
	
	public static boolean verifyAccountName(String fileName) {
		if (fileName.length() < 1 || fileName.length() > 122) 
			return false; 
		
		for (String c : fileName.split("")) {
			if(!c.matches("[_\\-\\.0-9a-z]")) 
				return false;
		}
		return true;
	}
	
	public static boolean verifyIPAddress(String ipAddress) {
		String[] addressSeparated = ipAddress.split("\\."); 	
		if (addressSeparated.length != 4) 
			return false;
		
		for (String ipNumber : addressSeparated) {
			int num;
			try {
				num = Integer.parseInt(ipNumber);
			} catch (NumberFormatException e) {
				return false;
			}
			if(num < 0 || num > 255)
				return false;
		}
		return true;
	}

	public static boolean verifyAmount(String amount) {
		
		String[] amountSeparated = amount.split("\\.");
		if (amountSeparated.length != 2) 
			return false;
		
		String wholeAmount = amountSeparated[0];
		String fractionalPart = amountSeparated[1];
		
		if (fractionalPart.length() != 2)
			return false;
			
		double amountInDouble = 0.0;
		try {
			amountInDouble = Double.parseDouble(amount);	
		} catch (NumberFormatException e) {
			return false;
		}
		
		if (amountInDouble >= 1 && wholeAmount.charAt(0) == '0')
			return false;
		
		if (amountInDouble < 0 || amountInDouble > 4294967295.99) {
			return false;
		}

		return true;
	}
}
