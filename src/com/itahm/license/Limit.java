package com.itahm.license;

public class Limit {

	private final long limit;
	private long count = 0;
	
	public Limit() {
		this(0);
	}
	
	public Limit(long l) {
		limit = l;
	}
	
	public synchronized boolean add() {
		if (this.limit > 0 && count == limit) {
			return false;
		}
		
		count++;
			
		return true;
	}
	
	public synchronized void remove() {
		count--;
	}
	
}
