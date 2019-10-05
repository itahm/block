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
			super(Event.CRITICAL, id, critical? Event.ERROR: Event.NORMAL, String.format("%s 임계 %s", title, critical? "초과": "정상"));
			
			this.index = index;
			this.oid = oid;
			this.critical = critical;
		}
	}
	
	public static class Event {
		public static final String STATUS = "status";
		public static final String SNMP = "snmp";
		public static final String REGISTER = "register";
		public static final String SEARCH = "search";
		public static final String CRITICAL = "critical";
		public static final String SYSTEM = "system";
		public static final String CHANGE = "change";
		
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
		public boolean smtpEnable = false;
		public String smtpServer;
		public String smtpProtocol;
		public String smtpUser;
		public String smtpPassword;
		
		public JSONObject getJSONObject() {
			JSONObject config = new JSONObject();
			
			config
				.put("requestInterval", this.requestInterval)
				.put("timeout", this.timeout)
				.put("retry", this.retry)
				.put("saveInterval", this.saveInterval)
				.put("storeDate", this.storeDate)
				.put("smtpEnable", this.smtpEnable);
			
			if (this.smtpServer != null) {
				config.put("smtpServer", this.smtpServer);
			}
			
			if (this.smtpProtocol != null) {
				config.put("smtpProtocol", this.smtpProtocol);
			}
			
			if (this.smtpUser != null) {
				config.put("smtpUser", this.smtpUser);
			}
			
			if (this.smtpPassword != null) {
				config.put("smtpPassword", this.smtpPassword);
			}
			
			return config;
		}
	}
}
