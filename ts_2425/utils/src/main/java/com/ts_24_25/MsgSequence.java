package com.ts_24_25;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class MsgSequence implements java.io.Serializable {
    private byte[] msg;
    private int seqNumber;

    public MsgSequence(byte[] msg, int seqNumber) {
        this.msg = msg;
        this.seqNumber = seqNumber;
    }

    public byte[] getMsg() {
        return msg;
    }

    public int getSeqNumber() {
        return seqNumber;
    }

    public void setMsg(byte[] msg) {
        this.msg = msg;
    }

    public void setSeqNumber(int seqNumber) {
        this.seqNumber = seqNumber;
    }

    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(this);
        objectOutputStream.flush();
        objectOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    public static MsgSequence fromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        MsgSequence obj = (MsgSequence) objectInputStream.readObject();
        objectInputStream.close();
        return obj;
    }
}
