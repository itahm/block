package com.itahm.block.node;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import com.itahm.util.Listener;

abstract public class Node implements Runnable, Closeable {

	public final long id;
	protected boolean isClosed = false;
	protected int
		timeout = 5000,
		retry = 1;
	protected final Thread thread;
	private final BlockingQueue<Long> queue = new LinkedBlockingQueue<>();
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	
	public Node(long id) {
		this.id = id;
		
		thread = new Thread(this);
		thread.start();
	}

	@Override
	public void run() {
		long delay, sent;
		
		loop: while (!this.thread.isInterrupted()) {
			try {
				delay = this.queue.take();
				
				if (delay > 0) {
					Thread.sleep(delay);
				}
				else if (delay < 0) {
					throw new InterruptedException();
				}
				
				for (int i=-1; i<this.retry; i++) {
					if (this.thread.isInterrupted()) {
						break loop;
					}
					
					try {
						sent = System.currentTimeMillis();
						
						if (isReachable()) {
							fireEvent(Event.PING, System.currentTimeMillis() - sent);
							
							continue loop;
						}
					} catch (IOException ie) {
						System.err.print(ie);
					}
				}
				
				fireEvent(Event.PING, -1);
			} catch (InterruptedException ie) {
				if (!this.isClosed) {
					System.err.print(ie);
				}
				
				break;
			}
		}
	}
	
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);
	}
	
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}

	public void fireEvent(Object ...args) {
		for (Listener listener: this.listenerList) {
			listener.onEvent(this, args);
		}
	}
	
	public void setHealth(int timeout, int retry) {
		this.timeout = timeout;
		this.retry = retry;
	}
	
	public void ping(long delay) {
		try {
			this.queue.put(delay);
		} catch (InterruptedException ie) {
			this.thread.interrupt();
		}
	}
	
	@Override
	public void close() {
		close(false);
	}
	
	public void close(boolean wait) {
		this.isClosed = true;
		
		this.thread.interrupt();
		
		if (wait) {
			try {
				this.thread.join();
			} catch (InterruptedException ie) {
				this.thread.interrupt();
			}
		}
	}
	
	abstract public boolean isReachable() throws IOException;
}
