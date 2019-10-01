package com.itahm.block;

import com.itahm.json.JSONArray;
import com.itahm.json.JSONObject;
import com.itahm.util.Listener;

public interface Commander {
	public boolean addAccount(String username, JSONObject account);
	public void addEventListener(Listener listener);
	public JSONObject addIcon(String type, JSONObject icon);
	public boolean addLink(long nodeFrom, long nodeTo);
	public JSONObject addNode(JSONObject node);
	public boolean addPath(long nodeFrom, long nodeTo);
	public boolean addProfile(String name, JSONObject profile);
	public boolean addUser(String name, JSONObject user);
	public void close();
	public JSONObject getAccount(String username);
	public JSONObject getAccount();
	public JSONObject getConfig();
	public JSONObject getEvent(long eventID);
	public JSONObject getEventByDate(long date);
	public JSONObject getIcon();
	public JSONObject getIcon(String type);
	public JSONObject getInformation();
	public JSONObject getLink();
	public JSONObject getLink(long nodeFrom, long nodeTo);
	public JSONObject getNode();
	public JSONObject getNode(long id, boolean snmp);
	public JSONObject getPath();
	public JSONObject getPath(long nodeFrom, long nodeTo);
	public JSONObject getPosition(String name);
	public JSONObject getProfile();
	public JSONObject getProfile(String name);
	public JSONObject getResource(long id, int index, String oid, long date, boolean summary);
	public JSONObject getSetting();
	public JSONObject getSetting(String key);
	public JSONObject getTop(JSONArray list, JSONObject resources);
	public JSONObject getTraffic(JSONObject traffic);
	public JSONObject getUser();
	public JSONObject getUser(String name);
	public boolean setAccount(String username, JSONObject account);
	public boolean setCritical(long id, String index, String oid, int critical);
	public boolean setIcon(String id, JSONObject icon);
	public boolean setLink(long nodeFrom, long nodeTo, JSONObject link);
	public boolean setMonitor(long id, String ip, String protocol);
	public boolean setNode(long id, JSONObject node);
	public boolean setPath(long nodeFrom, long nodeTo, JSONObject path);
	public boolean setPosition(String name, JSONObject position);
	public boolean setRetry(int retry);
	public boolean setRequestInterval(long interval);
	public boolean setSaveInterval(int interval);
	public boolean setSetting(String key, String value);
	public SMTP setSMTPServer(JSONObject smtp);
	public boolean setResource(long id, String index, String oid, String value);
	public boolean setStoreDate(int period);
	public boolean setTimeout(int timeout);
	public boolean setUser(String id, JSONObject user);
	public void start() throws Exception;
	public boolean removeAccount(String username);
	public void removeEventListener(Listener listener);
	public boolean removeIcon(String type);
	public boolean removeLink(long id);
	public boolean removeNode(long id);
	public boolean removePath(long nodeFrom, long nodeTo);
	public boolean removeProfile(String name);
	public boolean removeResource(long id, String index, String oid);
	public boolean removeUser(String name);
	public boolean search(String network, int mask);
}
