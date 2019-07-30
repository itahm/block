package com.itahm.block.node;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ICMPNode extends Node {

	private final InetAddress ip;
	
	public ICMPNode(long id, String ip) throws UnknownHostException {
		super(id);
		
		super.thread.setName(String.format("ICMPNode %s", ip));
		
		this.ip = InetAddress.getByName(ip);
	}

	@Override
	public boolean isReachable() {
		try {
			return this.ip.isReachable(super.timeout);
		}
		catch(IOException ioe) {
			return false;
		}
	}
}
