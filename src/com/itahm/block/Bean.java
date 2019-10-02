package com.itahm.block;

import com.itahm.json.JSONObject;

public class Bean {
	public static class Value {
		public long timestamp;
		public String value;
		public int limit;
		public boolean critical;
		
		public Value (long timestamp, String value) {
			this(timestamp, value, 0, false);
		}
		
		public Value (long timestamp, String value, int limit, boolean critical) {
			this.timestamp = timestamp;
			this.value = value;
			this.limit = limit;
			this.critical = critical;
		}
	}
	
	public static class Max {
		public final long id;
		public final int index;
		public final String value;
		public final long rate;
		
		public Max (long id, int index, String value) {
			this(id,  index,  value, -1);
		}
		
		public Max (long id, int index, String value, long rate) {
			this.id = id;
			this.index = index;
			this.value = value;
			this.rate = rate;
		}
	}
	
	public static class Rule {
		public final String oid;
		public final String name;
		public final String syntax;
		public final boolean rolling;
		public final boolean onChange;
		
		public Rule(String oid, String name, String syntax, boolean rolling, boolean onChange) {
			this.oid = oid;
			this.name = name;
			this.syntax = syntax;
			this.rolling = rolling;
			this.onChange = onChange;
		}
	}
	
	public static class CriticalEvent extends Event {
		public final String index;
		public final String oid;
		public final boolean critical;
		
		public CriticalEvent(long id, String index, String oid, boolean critical, String title) {
			super("critical", id, critical? Event.ERROR: Event.NORMAL, String.format("%s 임계 %s", title, critical? "초과": "정상"));
			
			this.index = index;
			this.oid = oid;
			this.critical = critical;
		}
	}
	
	public static class Event {
		public static final int NORMAL = 0;
		public static final int WARNING = 1;
		public static final int ERROR = 2;
		
		public final String origin;
		public final long id;
		public final int level;
		public String message;
		
		public Event(String origin, long id, int level, String message) {
			this.origin = origin;
			this.id = id;
			this.level = level;
			this.message = message;
		}
	}
	
	
	public static class Config {
		public long requestInterval = 10000L;
		public int timeout = 5000;
		public int retry = 2;
		public long saveInterval = 60000L *5;
		public long storeDate = 0L;
		
		public JSONObject getJSONObject() {
			return new JSONObject()
				.put("requestInterval", this.requestInterval)
				.put("timeout", this.timeout)
				.put("retry", this.retry)
				.put("saveInterval", this.saveInterval)
				.put("storeDate", this.storeDate);
		}
		
		public void set(String key, String value) {
			switch (key) {
			case "requestInterval":
				this.requestInterval = Long.valueOf(value);
			case "timeout":
				this.timeout = Integer.valueOf(value);
			case "retry":
				this.retry = Integer.valueOf(value);
			case "saveInterval":
				this.saveInterval = Long.valueOf(value);
			case "storeDate":
				this.storeDate = Long.valueOf(value);
			}
		}
		
		public String get(String key) {
			switch (key) {
			case "requestInterval":
				return Long.toString(this.requestInterval);
			case "timeout":
				return Integer.toString(this.timeout);
			case "retry":
				return Integer.toString(this.retry);
			case "saveInterval":
				return Long.toString(this.saveInterval);
			case "storeDate":
				return Long.toString(this.storeDate);
			}
			
			return null;
		}
	}
}
