package com.itahm.block;

import com.itahm.json.JSONObject;

public class Bean {
	public static class Value {
		public final long timestamp;
		public final String value;
		
		public Value (long timestamp, String value) {
			this.timestamp = timestamp;
			this.value = value;
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
	
	public static class Config {
		public long requestInterval = 10000L;
		public int timeout = 5000;
		public int retry = 2;
		public long saveInterval = 60000L;
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
