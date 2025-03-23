package com.ts_24_25;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class CommUtils {
	
    public static byte[] serializeBytes(Object object) {
		byte[] result = null;
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

		try {
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
			objectOutputStream.writeObject(object);

			objectOutputStream.flush();
            objectOutputStream.close();

            result = byteArrayOutputStream.toByteArray();
		} catch (IOException e) {
			System.exit(255);
		}

		return result;
	}
	
	public static Object deserializeBytes(byte[] objectInBytes) {
		Object result = null;

		try (ByteArrayInputStream bis = new ByteArrayInputStream(objectInBytes);
				ObjectInputStream ois = new ObjectInputStream(bis)) {

			result = ois.readObject();
		} catch (IOException | ClassNotFoundException e) {
			System.exit(255);
		}
        
		return result;
	}
}
