package com.ts_24_25;
public class MsgSequence {
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
}
