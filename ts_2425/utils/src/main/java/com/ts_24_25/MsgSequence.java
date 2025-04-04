package com.ts_24_25;

import java.io.Serializable;

public class MsgSequence implements Serializable{
    private byte[] msg;
    private long seqNumber;

    public MsgSequence(byte[] msg, long seqNumber) {
        this.msg = msg;
        this.seqNumber = seqNumber;
    }

    public byte[] getMsg() {
        return msg;
    }

    public long getSeqNumber() {
        return seqNumber;
    }

    public void setMsg(byte[] msg) {
        this.msg = msg;
    }

    public void setSeqNumber(long seqNumber) {
        this.seqNumber = seqNumber;
    }
}
