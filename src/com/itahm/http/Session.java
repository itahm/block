package com.itahm.http;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class Session {

	public static final String ID = "ITAhMSSID";
	private static final Map<String, Session> sessions = new ConcurrentHashMap<>();
	private static final Timer timer = new Timer("ITAhM Session timer", true);
	
	private final Map<String, Object> attribute = new HashMap<>();
	private long timeout = 3600000L;
	public final String id;
	private TimerTask task;
	
	public Session() {
		this(UUID.randomUUID().toString());
	}
	
	public Session(String id) {
		this.id = id;
		
		sessions.put(id, this);
		
		update();
	}
	
	public static int count() {
		return sessions.size();
	}
	
	public static Session find(String id) {
		return sessions.get(id);
	}
	
	public void setMaxInactiveInterval(long timeout) {
		this.timeout = timeout * 1000;
		
		update();
	}
	
	public Session update() {
		if (this.task != null) {
			this.task.cancel();
		}
		
		this.task = new TimerTask() {

			@Override
			public void run() {
				sessions.remove(id);
			}
		};
		
		try {
			timer.schedule(this.task, timeout);
		}
		catch (IllegalStateException ise) {
			return null;
		}
		
		return this;
	}
	
	public void setAttribute(String name, Object value) {
		this.attribute.put(name, value);
	}
	
	public Object getAttribute(String name) {
		return this.attribute.get(name);
	}
	
	public void invalidate() {
		this.task.cancel();
		
		sessions.remove(id);
	}
	
}
