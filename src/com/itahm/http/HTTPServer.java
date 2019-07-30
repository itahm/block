package com.itahm.http;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public abstract class HTTPServer implements Runnable, Closeable {
	
	private final static int BUF_SIZE = 2048;
	private final ServerSocketChannel channel;
	private final ServerSocket listener;
	private final Selector selector;
	private final ByteBuffer buffer;
	private final Set<Connection> connections = new HashSet<Connection>();
	
	private Boolean closed = false;

	public HTTPServer() throws IOException {
		this("0.0.0.0", 2014);
	}
	
	public HTTPServer(String ip) throws IOException {
		this(ip, 2014);
	}

	public HTTPServer(int tcp) throws IOException {
		this("0.0.0.0", tcp);
	}
	
	public HTTPServer(String ip, int tcp) throws IOException {
		channel = ServerSocketChannel.open();
		listener = channel.socket();
		selector = Selector.open();
		buffer = ByteBuffer.allocateDirect(BUF_SIZE);
		
		listener.bind(new InetSocketAddress(
			InetAddress.getByName(ip), tcp));
		
		channel.configureBlocking(false);
		channel.register(selector, SelectionKey.OP_ACCEPT);
		
		Thread t = new Thread(this);
		
		t.setName("ITAhM HTTP Listener");
		
		t.start();
	}
	
	private void onConnect() throws IOException {
		SocketChannel channel = null;
		Connection connection;
		
		try {
			channel = this.channel.accept();
			connection = new Connection(channel, this);
			
			channel.configureBlocking(false);
			channel.register(this.selector, SelectionKey.OP_READ, connection);
			
			connections.add(connection);
		} catch (IOException ioe) {
			if (channel != null) {
				channel.close();
			}
			
			throw ioe;
		}
	}
	
	private void onRead(SelectionKey key) throws IOException {
		SocketChannel channel = (SocketChannel)key.channel();
		Connection connection = (Connection)key.attachment();
		int bytes = 0;
		
		this.buffer.clear();
		
		bytes = channel.read(buffer);
		
		if (bytes == -1) {
			closeRequest(connection);
		}
		else if (bytes > 0) {
			this.buffer.flip();
				
			connection.parse(this.buffer);
		}
	}

	public void closeRequest(Connection connection) throws IOException {
		connection.close();
		
		connections.remove(connection);
	}
	
	public int getConnectionSize() {
		return connections.size();
	}
	
	@Override
	public void close() throws IOException {
		synchronized (this.closed) {
			if (this.closed) {
				return;
			}
		
			this.closed = true;
		}
		
		for (Connection connection : connections) {
			connection.close();
		}
			
		connections.clear();
		
		this.selector.wakeup();
	}

	@Override
	public void run() {
		Iterator<SelectionKey> iterator = null;
		SelectionKey key = null;
		int count;
		
		while(!this.closed) {
			try {
				count = this.selector.select();
			} catch (IOException ioe) {
				System.err.print(ioe);
				
				continue;
			}
			
			if (count > 0) {
				iterator = this.selector.selectedKeys().iterator();
				while(iterator.hasNext()) {
					key = iterator.next();
					iterator.remove();
					
					if (!key.isValid()) {
						continue;
					}
					
					if (key.isAcceptable()) {
						try {
							onConnect();
						} catch (IOException ioe) {
							System.err.print(ioe);
						}
					}
					else if (key.isReadable()) {
						try {
							onRead(key);
						}
						catch (IOException ioe) {
							System.err.print(ioe);
							
							try {
								closeRequest((Connection)key.attachment());
							} catch (IOException ioe2) {
								System.err.print(ioe2);
							}
						}
					}
				}
			}
		}
		
		try {
			this.selector.close();
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
		
		try {
			this.listener.close();
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
	}
	
	abstract public void doPost(Request connection, Response response);	
	abstract public void doGet(Request connection, Response response);
}
