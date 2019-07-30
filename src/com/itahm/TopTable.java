package com.itahm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.itahm.json.JSONArray;
import com.itahm.json.JSONObject;

public class TopTable {
	
	public enum Resource {
		RESPONSETIME("responseTime"),
		PROCESSOR("processor"),
		MEMORY("memory"),
		MEMORYRATE("memoryRate", true),
		STORAGE("storage"),
		STORAGERATE("storageRate", true),
		THROUGHPUT("throughput"),
		THROUGHPUTRATE("throughputRate", true),
		THROUGHPUTERR("throughputErr");
		
		private final String resource;
		private final boolean byRate;
		
		private Resource(String resource) {
			this(resource, false);
		}
		
		private Resource(String resource, boolean byRate) {
			this.resource = resource;
			this.byRate = byRate;
		}
		
		public String toString() {
			return this.resource;
		}
	};
	
	private final Map<Resource, HashMap<String, Value>> map = new ConcurrentHashMap<> ();
	
	public TopTable() {
		for (Resource key : Resource.values()) {
			map.put(key, new HashMap<String, Value>());
		}
	}
	
	public void submit(Resource resource, String id, Value value) {
		this.map.get(resource).put(id, value);
	}
	
	public JSONObject getTop(int limit, JSONArray src) {
		JSONObject top = new JSONObject();
		JSONArray resourceTop;
		Map<String, Value> map;
		List<String> list;
		String id;
		
		for (Resource resource : Resource.values()) {
			resourceTop = new JSONArray();
			list = new ArrayList<String>();
			
			map = this.map.get(resource);
			
			for (int i=0, _i= src.length(); i<_i ; i++) {
				id = src.getString(i);
				
				if (map.containsKey(id)) {
					list.add(id);
				}
			}
			
			Collections.sort(list, resource.byRate? new SortByRate(map): new SortByValue(map));
		
			for (int i=0, _i= list.size(), n=0; i<_i && n<limit; i++) {
				id = list.get(i);
				
				resourceTop.put(new JSONObject().put(id, map.get(id).toJSONObject()));
				
				n++;
			}
			
			top.put(resource.toString(), resourceTop);
		}
		
		return top;
	}
	
	public JSONObject getTop(int limit) {
		JSONObject top = new JSONObject();
		JSONArray resourceTop;
		Map<String, Value> map;
		List<String> list;
		String id;
		
		for (Resource resource : Resource.values()) {
			resourceTop = new JSONArray();
			list = new ArrayList<String>();
			
			map = this.map.get(resource);
			
			list.addAll(map.keySet());
			
			Collections.sort(list, resource.byRate? new SortByRate(map): new SortByValue(map));
		
			for (int i=0, _i= list.size(), n=0; i<_i && n<limit; i++) {
				id = list.get(i);
				
				resourceTop.put(new JSONObject().put(id, map.get(id).toJSONObject()));
				
				n++;
			}
			
			top.put(resource.toString(), resourceTop);
		}
		
		return top;
	}
	
	public void remove(String id) {
		for (Resource resource: Resource.values()) {
			this.map.get(resource).remove(id);
		}
	}
	
	public final static class Value {
		public final long value;
		public final long rate;
		public final long index;
		/**
		 * 
		 * @param value
		 * @param rate
		 * @param index
		 */
		public Value(long value, long rate, String index) {
			this.value = value;
			this.rate = rate;
			this.index = Long.parseLong(index);
		}
		
		public JSONObject toJSONObject() {
			return new JSONObject()
				.put("value", this.value)
				.put("rate", this.rate)
				.put("index", this.index);
		}
	}

	class SortByValue implements Comparator<String> {
		private final Map<String, Value> map;
		
		public SortByValue (Map<String, Value> map) {
			this.map = map;
		}
		
		@Override
		public int compare(String ip1, String ip2) {
			Value
				v1 = map.get(ip1),
				v2 = map.get(ip2);
			
			if (v1 == null && v2 == null) {
				return 0;
			}
			
			if (v1 == null) {
				return 1;
			}
			
			if (v2 == null) {
				return -1;
			}
			
			long l = v2.value - v1.value;
				
			if (l == 0) {
				l = v2.rate - v1.rate;
			}
			
			return l > 0? 1: l < 0? -1: 0;
		}
	}
	
	class SortByRate implements Comparator<String> {
		private final Map<String, Value> map;
		
		public SortByRate (Map<String, Value> map) {
			this.map = map;
		}
		
		@Override
		public int compare(String ip1, String ip2) {
			Value
				v1 = map.get(ip1),
				v2 = map.get(ip2);
			
			if (v1 == null && v2 == null) {
				return 0;
			}
			
			if (v1 == null) {
				return 1;
			}
			
			if (v2 == null) {
				return -1;
			}
			
			long l = v2.rate - v1.rate;
				
			if (l == 0) {
				l = v2.value - v1.value;
			}
			
			return l > 0? 1: l < 0? -1: 0;
		}
	}
}