package com.itahm.block;

import java.util.HashMap;
import java.util.Map;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

public class Memory {
	private final JSONObject account = new JSONObject();
	private final JSONObject config = new JSONObject();
	private final JSONObject icon = new JSONObject();
	private final JSONObject line = new JSONObject();
	private final JSONObject monitor = new JSONObject();
	private final JSONObject node = new JSONObject();
	private final JSONObject position = new JSONObject();
	private final JSONObject profile = new JSONObject();
	private final JSONObject setting = new JSONObject();
	private final JSONObject user = new JSONObject();
	
	private final Map<String, Long> ipIndex = new HashMap<>();
	
	public void addAccount(String username, JSONObject account) {
		this.account.put(username, account);
	}
	
	public void addConfig(String key, String value) {
		this.config.put(key, value);
	}
	
	public void addIcon(String type, JSONObject icon) {
		this.icon.put(type, icon);
		
	}
	
	public void addLine(String id, JSONObject line) {
		this.line.put(id, line);
	}
	
	public void addMonitor(long id, JSONObject monitor) {
		this.monitor.put(Long.toString(id), monitor);
	}
	
	public boolean addNode(long id, JSONObject node) {
		synchronized(this.node) {
			synchronized(this.ipIndex) {
				if (this.node.has(Long.toString(id))) {
					return false;
				}
				
				if (node.has("ip")) {
					this.ipIndex.put(node.getString("ip"), id);
				}
				
				this.node.put(Long.toString(id), node);
			}
		}
		
		return true;
	}
	
	public void addPosition(String name, String position) {
		this.position.put(name, position);
	}

	public void addProfile(String name, JSONObject profile) {
		this.position.put(name, profile);
	}
	
	public void addRe(String name, JSONObject profile) {
		this.position.put(name, profile);
	}
	
	public void addUser(String name, JSONObject user) {
		this.user.put(name, user);
	}

	public JSONObject getAccountAll() {
		return this.account;
	}
	
	public JSONObject getAccountByUsername(String username) {
		return this.account.getJSONObject(username);
	}
	
	public int getAccountSize() {
		return this.account.length();
	}
	
	public JSONObject getConfigAll() {
		return this.config;
	}
	
	public JSONObject getIconAll() {
		return this.icon;
	}
	
	public JSONObject getLineAll() {
		return this.line;
	}
	
	public JSONObject getMonitorAll() {
		return this.monitor;
	}
	
	public JSONObject getMonitorByID(long id) {
		try {
			return this.monitor.getJSONObject(Long.toString(id));
		}
		catch (JSONException jsone) {}
		
		return null;
	}
	
	public JSONObject getNodeAll() {
		return this.node;
	}

	public JSONObject getNodeByID(long id) {
		try {
			return this.node.getJSONObject(Long.toString(id));
		}
		catch (JSONException jsone) {}
		
		return null;
	}
	
	public JSONObject getNodeByIP(String ip) {
		Long id = this.ipIndex.get(ip);
		
		if (id != null) {
			return getNodeByID(id);
		}
		
		return null; 
	}
	
	public JSONObject getPositionAll() {
		return this.position;
	}
	
	public JSONObject copyPositionbyName(String name) {
		try {
			return new JSONObject(this.position.getString(name));
		}
		catch (JSONException jsone) {
		}
		
		return null;
	}

	public int getPositionSize() {
		return this.position.length();
	}

	public JSONObject getProfileAll() {
		return this.profile;
	}
	
	public JSONObject getProfileByName(String name) {
		return this.profile.getJSONObject(name);
	}
	
	
	public int getProfileSize() {
		return this.profile.length();
	}
	
	public JSONObject getSettingAll() {
		return this.setting;
	}
	
	public JSONObject getUserAll() {
		return this.user;
	}
	
	public JSONObject removeAccount(String username) {
		synchronized(this.account) {
			if (!this.account.has(username)) {
				return null;
			}
			
			JSONObject account = this.account.getJSONObject(username);
			boolean lastRoot = false;
	
			if (account.getInt("level") == 0) {
				lastRoot = true;
				
				for (Object o: this.account.keySet()) {
					if (username.equals(o)) {
						continue;
					};
					
					if (this.account.getJSONObject((String)o).getInt("level") == 0) {
						lastRoot = false;
						
						break;
					}
				}
			}
			
			if (lastRoot) {
				return null;
			}
			
			return (JSONObject)this.account.remove(username);
		}
	}
	/*
	public boolean removeConfig(String ...keys) {
		String [][] backup = new String[keys.length][2];
		String old;
		int i=0;
		
		for (String key : keys) {
			old = (String)this.config.remove(key);
			
			if (old == null) {
				for (int j=0; j<i; j++) {
					this.config.put(backup[j][0], backup[j][1]);
				}
				
				return false;
			}
			
			backup[i++] = new String [] {key, old};
		}
		
		return true;
	}
	*/
	
	public String removeConfig(String key) {
		return (String)this.config.remove(key);
	}
	
	public JSONObject removeIcon(String type) {
		return (JSONObject)this.icon.remove(type);
	}
	
	public void removeLine(String id) {
		this.line.remove(id);
	}
	
	public JSONObject removeMonitor(long id) {
		return (JSONObject)this.monitor.remove(Long.toString(id));
	}
	
	public JSONObject removeNode(long id) {
		synchronized(this.node) {
			synchronized(this.ipIndex) {
				if (!this.node.has(Long.toString(id))) {
					return null;
				}
				
				JSONObject node = this.node.getJSONObject(Long.toString(id));
				
				if (node.has("ip")) {
					this.ipIndex.remove(node.getString("ip"));
				}
				
				return (JSONObject)this.node.remove(Long.toString(id));
			}
		}
	}
	
	public String removePosition(String name) {
		return (String)this.position.remove(name);
	}
	
	public JSONObject removeProfile(String name) {
		return (JSONObject)this.profile.remove(name);
	}
	
	public void removeSetting(String key) {
		this.setting.remove(key);
	}
	
	public JSONObject removeUser(String name) {
		return (JSONObject)this.user.remove(name);
	}
	
	public boolean setAccount(String username, JSONObject account) {
		synchronized(this.account) {
			if (!this.account.has(username)) {
				return false;
			}
			
			JSONObject old = this.account.getJSONObject(username);
			
			if (old.getInt("level") == 0 && old.getInt("level") != account.getInt("level")) {
				boolean lastRoot = true;
				
				for (Object o: this.account.keySet()) {
					if (this.account.getJSONObject((String)o).getInt("level") == 0) {
						lastRoot = false;
						
						break;
					}
				}
				
				if (lastRoot) {
					return false;
				}
			}
			
			this.config.put(username, account);
		}
		
		return true;
	}
	
	public void setConfig(String key, String value) {
		this.config.put(key, value);
	}

	public void setIcon(String type, JSONObject icon) {
		this.icon.put(type, icon);
	}
	
	public void setMonitor(long id, JSONObject monitor) {
		this.monitor.put(Long.toString(id), monitor);
	}
	
	public void setPosition(String name, String position) {
		this.position.put(name, position);
	}
	
	public void setSetting(String key, String value) {
		this.setting.put(key, value);
	}
	
	public void setUser(String name, JSONObject user) {
		this.user.put(name, user);
	}
	
}
