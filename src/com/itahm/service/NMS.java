package com.itahm.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

import javax.mail.MessagingException;

import com.itahm.http.Response;
import com.itahm.json.JSONArray;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.lang.KR;
import com.itahm.nms.Commander;
import com.itahm.nms.H2Agent;
import com.itahm.nms.Bean.Event;
import com.itahm.smtp.SMTP;
import com.itahm.util.Listener;

public class NMS implements Serviceable, Listener {

	private final static String VERSION = "ITAhM v3.0"/*"CeMS v1.0"*/;
	private byte [] event = null;
	private Commander agent;
	private SMTP smtp;
	private final Path root;
	
	public NMS(Path root) throws Exception {
		this.root = root;
	}
	
	private void setSMTP(JSONObject config) {
		if (config == null) {
			this.smtp = null;
		} else {
			this.smtp = new SMTP(config.getString("smtpServer"),
				config.getString("smtpProtocol"),
				config.getString("smtpUser"),
				config.getString("smtpPassword"));
			
			this.smtp.addEventListener(this);
		}
	}
	
	@Override
	synchronized public void stop() {
		if (this.agent == null) {
			return;
		}
		
		setSMTP(null);
		
		try {
			this.agent.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		
		this.agent = null;
	}

	@Override
	synchronized public void start() {
		try {
			this.agent = new H2Agent(root);
		
			JSONObject config = this.agent.getConfig();
			
			if (config.has("smtpEnable") && config.getBoolean("smtpEnable")) {
				setSMTP(config);
			}
			
			this.agent.addEventListener(this);
			
			this.agent.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	synchronized public void service(JSONObject request, Response response) {
		String command = request.getString("command").toUpperCase();
		
		if (this.agent == null) {
			response.setStatus(Response.Status.UNAVAILABLE);
			
			return;
		}
		
		try {
			switch (command) {				
			case "LISTEN":
					JSONObject event = null;
					
					if (request.has("eventID")) {
						event = this.agent.getEvent(request.getLong("eventID"));
					}
					
					if (event == null) {
						synchronized(this) {
							try {
								wait();
							} catch (InterruptedException ie) {
							}
							
							response.write(this.event);
						}
					}
					else {
						response.write(event.toString().getBytes(StandardCharsets.UTF_8.name()));
					}
				
				break;
			default:
				if (!parseRequest(command, request, response)) {
					throw new JSONException("Command not found.");
				}
			}
					
		} catch (JSONException | UnsupportedEncodingException e) {
			response.setStatus(Response.Status.BADREQUEST);
			
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
		}
	}
		
	@Override
	public void onEvent(Object caller, Object ...args) {
		JSONObject event = null;
		
		if (caller instanceof Commander) {
			event = (JSONObject)args[0];
		}
		else if (caller instanceof SMTP) {
			//MimeMessage mm = (MimeMessage)args[0];
			//MessagingException me = (MessagingException)args[1];
			
			this.agent.sendEvent(new Event(Event.SYSTEM, 0, Event.WARNING, KR.WARNING_SMTP_FAIL));
		}
		
		if (event == null) {
			return;
		}
		
		synchronized(this) {
			try {
				if (this.smtp != null) {
					ArrayList<String> list = new ArrayList<>();
					JSONObject
						userData = this.agent.getUser(),
						user;
					
					for (Object name : userData.keySet()) {
						user = userData.getJSONObject((String)name);
						
						if (user.has("email")) {
							list.add(user.getString("email"));
						}
					}
					
					if (list.size() > 0) {
						String [] sa = new String [list.size()];
						
						list.toArray(sa);
						
						try {
							this.smtp.send(event.getString("message"), sa);
						} catch (MessagingException me) {
							me.printStackTrace();
						}
					}
				}
				
				this.event = event.toString().getBytes(StandardCharsets.UTF_8.name());
				
				notifyAll();
			} catch (UnsupportedEncodingException uee) {}
		}
	}

	private boolean parseRequest(String command, JSONObject request, Response response) {
		try {
			switch(command) {
			case "ADD":
				add(request, response);
				
				break;
			case "ECHO": break;
			case "GET":
				get(request, response);
				
				break;			
			case "REMOVE":
				remove(request, response);
				
				break;
			case "SEARCH":
				this.agent.search(request.getString("network"), request.getInt("mask"));
				
				break;
			case "SET":
				set(request, response);
				
				break;
			default:
				response.write(new JSONObject().
					put("error", "Command not found.").toString());
				
				response.setStatus(Response.Status.BADREQUEST);
			}
		} catch (JSONException jsone) {
			response.write(new JSONObject().
				put("error", jsone.getMessage()).toString());
			
			response.setStatus(Response.Status.BADREQUEST);
			
		} catch (Exception e) {
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
			e.printStackTrace();
			response.setStatus(Response.Status.SERVERERROR);
		}
		
		return true;
	}
	
	private void add(JSONObject request, Response response) {
		boolean success = true;
		
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			success = this.agent.addAccount(request.getString("username"), request.getJSONObject("account"));
			
			break;
		case "ICON":
			if (this.agent.addIcon(request.getString("type"), request.getJSONObject("icon")) == null) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "LINK":
			if (!this.agent.addLink(request.getLong("nodeFrom"), request.getLong("nodeTo"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			break;
			
		case "NODE":
			JSONObject node = this.agent.addNode(request.getJSONObject("node"));
			
			if (node == null) {
				response.setStatus(Response.Status.CONFLICT);
			}
			else {
				response.write(node.toString());
			}
			
			break;
		case "PATH":
			if (!this.agent.addPath(request.getLong("nodeFrom"), request.getLong("nodeTo"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PROFILE":
			if (!this.agent.addProfile(request.getString("name"), request.getJSONObject("profile"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "USER":
			this.agent.addUser(request.getString("name"), request.getJSONObject("user"));
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
		
		if (!success) {
		}
	}
	
	private void set(JSONObject request, Response response) {
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			if (!this.agent.setAccount(request.getString("username"), request.getJSONObject("account"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "CONFIG":
			switch (request.getString("key")) {
			case "retry": 
				if (!this.agent.setRetry(request.getInt("value"))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
				
				break;
			case "storeDate":
				if (!this.agent.setStoreDate(Integer.valueOf(request.getString("value")))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
				
				break;
			case "saveInterval": 
				if (!this.agent.setSaveInterval(Integer.valueOf(request.getString("value")))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
				
				break;
			case "requestInterval": 
				if (!this.agent.setRequestInterval(request.getLong("value"))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
				
				break;
			case "snmpServer":
				if (this.smtp != null) {
					try {
						this.smtp.close();
					} catch (IOException ioe) {
						ioe.printStackTrace();
					}
					
					this.smtp = null;
				}
				
				if (!request.has("value")) {
					this.agent.setSMTP(null);
				} else if (this.agent.setSMTP(request.getJSONObject("value"))) {
					JSONObject config = this.agent.getConfig();
					
					setSMTP(config);
					
					try {
						this.smtp.send(KR.INFO_SMTP_INIT, config.getString("smtpUser"));
					} catch (MessagingException me) {
						response.setStatus(Response.Status.NOTIMPLEMENTED);
					}
				}
				
				break;
			case "timeout": 
				if (!this.agent.setTimeout(request.getInt("value"))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
			
				break;
			default:
				response.setStatus(Response.Status.BADREQUEST);
			}
			
			break;
		case "CRITICAL":
			if (!this.agent.setCritical(request.getLong("id"),
				request.getString("index"),
				request.getString("oid"),
				request.getInt("limit"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "ICON":
			if (!this.agent.setIcon(request.getString("type"), request.getJSONObject("icon"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "LINK":
			if (!this.agent.setLink(request.getLong("nodeFrom"), request.getLong("nodeTo"),request.getJSONObject("link"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PATH":
			if (!this.agent.setPath(request.getLong("nodeFrom"), request.getLong("nodeTo"), request.getJSONObject("path"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "MONITOR":
			if (!this.agent.setMonitor(request.getLong("id"), request.getString("ip"), request.has("protocol")? request.getString("protocol"): null)) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "NODE":
			if (!this.agent.setNode(request.getLong("id"), request.getJSONObject("node"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "POSITION":
			if (!this.agent.setPosition(request.getString("name"), request.getJSONObject("position"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "SETTING":
			if (!this.agent.setSetting(request.getString("key"), request.has("value")? request.getString("value"): null)) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "RESOURCE":
			if (request.has("value")) {
				if (!this.agent.setResource(request.getLong("id"),
					request.getString("index"),
					request.getString("oid"),
					request.getString("value"))) {
					response.setStatus(Response.Status.CONFLICT);
				}
			} else {
				if (!this.agent.removeResource(request.getLong("id"),
					request.getString("index"),
					request.getString("oid"))) {
					response.setStatus(Response.Status.CONFLICT);
				}
			}
			
			break;
		case "USER":
			if (!this.agent.setUser(request.getString("name"), request.getJSONObject("user"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
	}
	
	private void remove(JSONObject request, Response response) {
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			if(!this.agent.removeAccount(request.getString("username"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "ICON":
			if (!this.agent.removeIcon(request.getString("type"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "LINK":
			if (!this.agent.removeLink(request.getLong("id"))) {
				response.setStatus(Response.Status.CONFLICT);
			};
			
			break;
		case "NODE":
			if (!this.agent.removeNode(request.getLong("id"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PATH":
			if (!this.agent.removePath(request.getLong("nodeFrom"), request.getLong("nodeTo"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PROFILE":
			if (!this.agent.removeProfile(request.getString("name"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "USER":
			if (!this.agent.removeUser(request.getString("name"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
	}
	
	private void get(JSONObject request, Response response) {
		Object target = request.get("target");
		
		if (target instanceof JSONArray) {
			JSONArray targets = (JSONArray)target;
			JSONObject result = new JSONObject();
			
			for (int i=0, _i=targets.length(); i<_i; i++) {
				result.put(targets.getString(i), get(targets.getString(i), request));
			}
			
			response.write(result.toString());
		}
		else if (target instanceof String){
			JSONObject result = get((String)target, request);
			
			if (result == null) {
				response.setStatus(Response.Status.NOCONTENT);
			}
			else {
				response.write(result.toString());
			}
		}
		else {
			throw new JSONException("Target is not valid.");
		}
	}
	
	private JSONObject get(String target, JSONObject request) {
		switch(target.toUpperCase()) {
		case "ACCOUNT":
			return request.has("username")?
				this.agent.getAccount(request.getString("username")):
				this.agent.getAccount();
		case "CONFIG":
			return this.agent.getConfig();
		case "CRITICAL":
			return this.agent.getCritical(request.getLong("id"), request.getString("index"), request.getString("oid"));
		case "EVENT":
			return this.agent.getEventByDate(request.getLong("date"));
		case "ICON":
			return request.has("type")?
				this.agent.getIcon(request.getString("type")):
				this.agent.getIcon();
		case "INFORMATION":
			JSONObject result = this.agent.getInformation();
			
			result
				.put("version", VERSION)
				.put("java", System.getProperty("java.version"))
				//.put("expire", this.expire)
				.put("path", this.root.toString());
			try {
				result.put("space", Files.getFileStore(this.root).getUsableSpace());
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			
			return result;
		case "LINK":
			return request.has("nodeFrom")?
				this.agent.getLink(request.getLong("nodeFrom"), request.getLong("nodeTo")):
				this.agent.getLink();
		case "LOG":
			return this.agent.getEventByDate(request.getLong("date"));
		case "NODE":
			return request.has("id")?
				this.agent.getNode(request.getLong("id"), request.has("resource") && request.getBoolean("resource")):
				this.agent.getNode();
		case "PATH":
			return request.has("nodeFrom")?
				this.agent.getPath(request.getLong("nodeFrom"), request.getLong("nodeTo")):
				this.agent.getPath();
		case "POSITION":
			return this.agent.getPosition("position");
		case "PROFILE":
			return this.agent.getProfile();
		case "RESOURCE":
			return  this.agent.getResource(request.getLong("id"),
					request.getInt("index"),
					request.getString("oid"),
					request.getLong("date"),
					request.has("summary")? request.getBoolean("summary"): false);
		case "SETTING":
			return request.has("key")?
				this.agent.getSetting(request.getString("key")):
				this.agent.getSetting();
		case "TOP":
			return this.agent.getTop(request.getJSONArray("list"), request.getJSONObject("resource"));
		case "TRAFFIC":
			return this.agent.getTraffic(request.getJSONObject("traffic"));
		case "USER":
			return this.agent.getUser();
		default:
			
			throw new JSONException("Target is not found.");
		}
	}
}
