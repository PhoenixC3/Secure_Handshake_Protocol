package com.ts_24_25;

public class VerifyArgs {
    public static boolean verifyPort(String port) {
		if (port == null || port.isEmpty()) {
			return false;
		}
		port = port.trim();
	
		if (!port.matches("^[1-9][0-9]{0,4}$")) {
			return false;
		}
	
		int portNumber;
		try {
			portNumber = Integer.parseInt(port);
		} catch (NumberFormatException e) {
			return false;
		}
	
		return portNumber >= 1024 && portNumber <= 65535;
	}
	
	
	public static boolean verifyFileNames(String fileName) {
		return !(fileName.length() < 1 || fileName.length() > 127 || fileName.equals(".") || fileName.equals("..") || !fileName.matches("^[_\\-\\.0-9a-z]{1,127}$"));
	}
	
	public static boolean verifyAccountName(String fileName) {
		return !(fileName.length() < 1 || fileName.length() > 122 || !fileName.matches("^[_\\-\\.0-9a-z]{1,127}$"));
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
		if (!amount.matches("^(0|[1-9][0-9]{0,9})\\.[0-9]{2}$")) {
			return false;
		}
		double amountInDouble;
		try {
			amountInDouble = Double.parseDouble(amount);
		} catch (NumberFormatException e) {
			return false;
		}
		return amountInDouble >= 0.00 && amountInDouble <= 4294967295.99;
	}
	
}
