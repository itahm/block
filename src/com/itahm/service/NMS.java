package com.itahm.service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.lang.KR;
import com.itahm.nms.Commander;
import com.itahm.nms.H2Agent;
import com.itahm.smtp.SMTP;
import com.itahm.util.Listener;
import com.itahm.util.Util;

public class NMS implements Serviceable, Listener {

	private final static String VERSION = "CeMS v1.0";
	private Commander agent;
	private final SMTP smtpServer = new SMTP();
	private final Path root;
	private final long expire;
	private final int limit;
	private Boolean isClosed = true;
	private byte [] event = null;
	
	public NMS(Builder builder) throws Exception {
		root = builder.root;
		expire = builder.expire;
		limit = builder.limit;
		
		if (expire > 0) {
			Calendar c = Calendar.getInstance();
			
			if (expire < c.getTimeInMillis()) {
				throw new Exception("Expired License.");
			}
			
			c.setTimeInMillis(expire);
			
			System.out.format("License expires on %s.\n", new SimpleDateFormat("MMM dd, yyyy").format(c.getTime()));
			
			new Timer("Expire Scheduler").schedule(new TimerTask() {

				@Override
				public void run() {
					try {
						// TODO
						System.out.println(KR.ERROR_LICENSE_EXPIRE);
						
						agent.close();
					} catch (IOException ioe) {
						ioe.printStackTrace();
					}
					
				}}, new Date(expire));
		}
	}
	
	public static class Builder {
		private final Path root;
		private boolean licensed = true;
		private long expire = 0;
		private int limit = 0;
		
		public Builder (Path root) {
			this.root = root;
		}
		
		public Builder license(String mac) {
			if (!Util.isValidAddress(mac)) {
				System.out.println(KR.ERROR_LICENSE_MAC);
				
				licensed = false;
			}
			
			return this;
		}
		
		public Builder expire(long expire) {
			this.expire = expire;
			
			return this;
		}
		
		public Builder limit(int limit) {
			this.limit = limit;
			
			return this;
		}
		
		public NMS build() throws Exception {
			if (!this.licensed) {
				return null;
			}
			
			return new NMS(this);
		}
	}
	

	@Override
	public void start() {
		synchronized(this.isClosed) {
			if (!this.isClosed) {
				return;
			}
			
			try {
				this.agent = new H2Agent(this, this.root, this.limit);
			
				JSONObject config = this.agent.getConfig();
				
				if (config.has("smtpEnable") && config.getBoolean("smtpEnable")) {
					this.smtpServer.enable(config.getString("smtpServer"),
						config.getString("smtpProtocol"),
						config.getString("smtpUser"),
						config.getString("smtpPassword"));
				}
				
				this.agent.start();
				
				this.isClosed = false;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	@Override
	public void stop() {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
			
			try {
				this.agent.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			
			this.isClosed = true;
		}
	}

	@Override
	public boolean service(Request request, Response response, JSONObject data) {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return false;
			}
		}
	
		String command = data.getString("command").toUpperCase();
		
		try {
			switch (command) {				
			case "LISTEN":
					JSONObject event = null;
					
					if (data.has("eventID")) {
						event = this.agent.getEvent(data.getLong("eventID"));
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
			case "RESTORE":
				
				break;
			default:
				return parseRequest(command, data, response);
			}
			
		} catch (JSONException | UnsupportedEncodingException e) {
			response.setStatus(Response.Status.BADREQUEST);
			
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
		}
	
		return true;
	}
		
	@Override
	public void onEvent(Object caller, Object ...args) {
		JSONObject event = null;
		
		if (caller instanceof Commander) {
			event = (JSONObject)args[0];
		}
		
		if (event == null) {
			return;
		}
		
		synchronized(this) {
			try {
				JSONObject userData = this.agent.getUser();
				
				if (userData != null) {
					ArrayList<String> list = new ArrayList<>();
					JSONObject user;
					
					for (Object name : userData.keySet()) {
						user = userData.getJSONObject((String)name);
						
						if (user.has("email")) {
							list.add(user.getString("email"));
						}
					}
					
					if (list.size() > 0) {
						String [] sa = new String [list.size()];
						
						list.toArray(sa);
						
						this.smtpServer.send(event.getString("message"), sa);
					}
				}
				
				this.event = event.toString().getBytes(StandardCharsets.UTF_8.name());
				
				notifyAll();
			} catch (UnsupportedEncodingException uee) {
				uee.printStackTrace();
			}
		}
	}

	private boolean parseRequest(String command, JSONObject request, Response response) {
		try {
			switch(command) {
			case "ADD":
				add(request, response);
				
				break;
			case "BACKUP":
				if (request.getString("service").equalsIgnoreCase("NMS")) {
					this.agent.backup();
				} else {
					return false;
				}
				
				break;
			case "ECHO": break;
			case "GET":
				get(request, response);
				
				break;			
			case "REMOVE":
				remove(request, response);
				
				break;
			case "SEARCH":
				this.agent.search(
					request.getString("network"),
					request.getInt("mask"),
					request.has("profile")? request.getString("profile"): null);
				
				break;
			case "SET":
				set(request, response);
				
				break;
			default:
				return false;
			}
		} catch (JSONException jsone) {
			response.write(new JSONObject().
				put("error", jsone.getMessage()).toString());
			
			response.setStatus(Response.Status.BADREQUEST);
			
		} catch (Exception e) {
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
			
			response.setStatus(Response.Status.SERVERERROR);
		}
		
		return true;
	}
	
	private void add(JSONObject request, Response response) {
		switch(request.getString("target").toUpperCase()) {
		case "BODY":
			if (!this.agent.addBranch(request.getJSONObject("model"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "BRANCH":
			if (!this.agent.addBranch(request.getJSONObject("branch"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
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
		case "RACK":
			if (!this.agent.addRack(request.getJSONObject("rack"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "USER":
			if (!this.agent.addUser(request.getString("name"), request.getJSONObject("user"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
	}
	
	private void set(JSONObject request, Response response) {
		switch(request.getString("target").toUpperCase()) {
		case "BODY":
			if (!this.agent.setBody(request.getLong("id"), request.getJSONObject("model"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "BRANCH":
			if (!this.agent.setBranch(request.getLong("id"), request.getJSONObject("branch"))) {
				response.setStatus(Response.Status.SERVERERROR);
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
			case "smtpServer":
				if (!request.has("value")) {
					if (this.agent.setSMTP(null)) {
						this.smtpServer.disable();
					} else {
						response.setStatus(Response.Status.SERVERERROR);
					}
				} else {
					JSONObject smtp = request.getJSONObject("value");
					
					if (this.agent.setSMTP(smtp)) {
						if (!this.smtpServer.enable(
							smtp.getString("server"),
							smtp.getString("protocol"),
							smtp.getString("user"),
							smtp.getString("password")
						)) {
							// DB 는 수정 되었으나 정상동작하지 않는다. isRunning() = false
							response.setStatus(Response.Status.NOTIMPLEMENTED);
						}
					} else {
						response.setStatus(Response.Status.SERVERERROR);	
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
		case "LOCATION":
			if (!this.agent.setLocation(request.getLong("node"), request.getJSONObject("location"))) {
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
		case "PATH":
			if (!this.agent.setPath(request.getLong("nodeFrom"), request.getLong("nodeTo"), request.getJSONObject("path"))) {
				response.setStatus(Response.Status.CONFLICT);
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
		case "RACK":
			if (request.has("id")) {
				if (!this.agent.setRack(request.getInt("id"), request.getJSONObject("rack"))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
			} else {
				if (!this.agent.setRack(request.getJSONObject("rack"))) {
					response.setStatus(Response.Status.SERVERERROR);
				}
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
		case "BODY":
			if (!this.agent.removeBody(request.getLong("id"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "BRANCH":
			if (!this.agent.removeBranch(request.getLong("id"))) {
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
		case "LOCATION":
			if (!this.agent.removeLocation(request.getLong("node"))) {
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
		case "RACK":
			if (!this.agent.removeRack(request.getInt("id"))) {
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
		String target = request.getString("target");
		
		JSONObject result = get((String)target, request);
		
		if (result == null) {
			response.setStatus(Response.Status.NOCONTENT);
		}
		else {
			response.write(result.toString());
		}
	}
	
	private JSONObject get(String target, JSONObject request) {
		switch(target.toUpperCase()) {
		case "BODY":
			return request.has("id")?
				this.agent.getBody(request.getLong("id")):
				this.agent.getBody();
		case "BRANCH":
			return request.has("id")?
				this.agent.getBranch(request.getLong("id")):
				this.agent.getBranch();
		case "CONFIG":
			return this.agent.getConfig().put("smtpRunning", this.smtpServer.isRunning());
		case "CRITICAL":
			return this.agent.getCritical(request.getLong("id"), request.getString("index"), request.getString("oid"));
		case "EVENT":
			return request.has("date")?
				this.agent.getEventByDate(request.getLong("date")):
				this.agent.getEvent(request.getJSONObject("search"));
		case "ICON":
			return request.has("type")?
				this.agent.getIcon(request.getString("type")):
				this.agent.getIcon();
		case "INFORMATION":
			JSONObject result = this.agent.getInformation();
			
			result
				.put("version", VERSION)
				.put("java", System.getProperty("java.version"))
				.put("expire", this.expire)
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
		case "LOCATION":
			return request.has("node")?
				this.agent.getLocation(request.getLong("node")):
				this.agent.getLocation();
		case "LOG":
			return this.agent.getEventByDate(request.getLong("date"));
		case "NODE":
			return request.has("id")?
				this.agent.getNode(request.getLong("id"), request.has("resource") && request.getBoolean("resource")):
				this.agent.getNode(request.has("filter")? request.getString("filter"): null);
		case "PATH":
			return request.has("nodeFrom")?
				this.agent.getPath(request.getLong("nodeFrom"), request.getLong("nodeTo")):
				this.agent.getPath();
		case "POSITION":
			return this.agent.getPosition(request.has("name")? request.getString("name"): "position");
		case "PROFILE":
			return request.has("name")?
				this.agent.getProfile(request.getString("name")):
					this.agent.getProfile();
		case "RACK":
			return request.has("id")?
				this.agent.getRack(request.getInt("id")):
				this.agent.getRack();
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
			return this.agent.getTop(request.getInt("count"));
		case "TRAFFIC":
			return this.agent.getTraffic(request.getJSONObject("traffic"));
		case "USER":
			return request.has("name")?
				this.agent.getUser(request.getString("name")):
				this.agent.getUser();
		default:
			
			throw new JSONException("Target is not found.");
		}
	}
	
	@Override
	public boolean isRunning() {
		synchronized(this.isClosed) {
			return !this.isClosed;
		}
	}
}
