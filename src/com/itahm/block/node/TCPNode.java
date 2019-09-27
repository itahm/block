package com.itahm.block.node;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class TCPNode extends Node {

	private final InetSocketAddress target;
	
	public TCPNode(long id, String ip) throws UnknownHostException {
		this(id, ip, String.format("TCPNode %s", ip));
	}
	
	public TCPNode(long id, String ip, String name) throws UnknownHostException {
		super(id, name);
		
		String [] address = ip.split(":");
		
		if (address.length != 2) {
			throw new UnknownHostException(ip);
		}
		
		target = new InetSocketAddress(InetAddress.getByName(address[0]), Integer.parseInt(address[1]));
	}

	
	@Override
	public boolean isReachable() throws IOException {
		try (Socket socket = new Socket()) {
			socket.connect(this.target, super.timeout);
		} catch (IOException e) {	
			return false;
		}
		
		return true;
	}

}
