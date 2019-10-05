package com.itahm;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.regex.Pattern;

import javax.mail.MessagingException;

import com.itahm.http.Connection;
import com.itahm.http.HTTPServer;
import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.http.Session;
import com.itahm.json.JSONArray;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.license.Expire;
import com.itahm.util.Listener;
import com.itahm.util.Util;
import com.itahm.block.Commander;
import com.itahm.block.H2Agent;
import com.itahm.block.Lang;
import com.itahm.block.Bean.Event;
import com.itahm.smtp.SMTP;

public class ITAhM extends HTTPServer implements Listener {
	private enum Status {
		READY, RUN, STOP;
	};
	
	private byte [] event = null;
	private final static int SESS_TIMEOUT = 3600;
	private final static String VERSION = "CeMS v1.0";
	private final Path root;
	private Status agentStatus = Status.READY;
	public final int limit;
	public final long expire;
	private Commander agent;
	private SMTP smtp;
	
	private ITAhM(Builder builder) throws Exception {
		super(builder.ip, builder.tcp);
		
		System.out.format("ITAhM HTTP Server started with TCP %d.\n", builder.tcp);
		
		root = builder.root;
		limit = builder.limit;
		expire = builder.expire;
		
		if (expire > 0 && new Expire(expire, this).isExpired()) {
			throw new Exception("Check your License.Expire");
		}

		agent = new H2Agent(root.resolve("data"));
		
		JSONObject config = this.agent.getConfig();
		
		if (config.has("smtpEnable") && config.getBoolean("smtpEnable")) {
			setSMTP(config);
		}
		
		agent.addEventListener(this);
		
		agent.start();
		
		synchronized(agentStatus) {
			agentStatus = Status.RUN;
		}
	}

	public static class Builder {
		private String ip = "0.0.0.0";
		private int tcp = 2014;
		private Path root = null;
		private boolean licensed = true;
		private long expire = 0;
		private int limit = 0;
		
		public Builder() {
		}
		
		public Builder tcp(int i) {
			tcp = i;
			
			return this;
		}
		
		public Builder root(String path) {
			try {
				root = Path.of(path);
			}
			catch(InvalidPathException ipe) {
			}
			
			return this;
		}
		
		public Builder license(String mac) {
			if (!Util.isValidAddress(mac)) {
				System.out.println("Check your License.MAC");
				
				licensed = false;
			}
			
			return this;
		}
		
		public Builder expire(long ms) {
			
			expire = ms;
			
			return this;
		}
		
		public Builder limit(int n) {
			limit = n;
			
			return this;
		}
		
		public ITAhM build() throws Exception {
			if (!this.licensed) {
				return null;
			}
			
			if (this.root == null) {
				this.root = Path.of(ITAhM.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
			}
			
			return new ITAhM(this);
		}
	}
	
	@Override
	public void doGet(Request request, Response response) {
		String uri = request.getRequestURI();
		
		if ("/".equals(uri)) {
			uri = "/index.html";
		}
		
		Path path = this.root.resolve(uri.substring(1));
		
		if (!Pattern.compile("^/data/.*").matcher(uri).matches() && Files.isRegularFile(path)) {
			try {
				response.write(path);
			} catch (IOException e) {
				response.setStatus(Response.Status.SERVERERROR);
			}
		}
		else {
			response.setStatus(Response.Status.NOTFOUND);
		}
	}
	
	@Override
	public void doPost(Request request, Response response) {		
		String origin = request.getHeader(Connection.Header.ORIGIN.toString());
		
		if (origin != null) {
			response.setHeader("Access-Control-Allow-Origin", origin);
			response.setHeader("Access-Control-Allow-Credentials", "true");
		}
		
		JSONObject data;
		String command;
		try {
			data = new JSONObject(new String(request.read(), StandardCharsets.UTF_8.name()));
			
			if (!data.has("command")) {
				throw new JSONException("Command not found.");
			}
			
			command = data.getString("command").toUpperCase();
			
			Session session = request.getSession(false);
			
			synchronized(this.agentStatus) {
				if (this.agentStatus == Status.STOP) {
					if ("START".equals(command)) {
						if (session == null) {
							response.setStatus(Response.Status.UNAUTHORIZED);
						}
						else {
							this.agentStatus = Status.READY;
							
							try {
								this.agent = new H2Agent(this.root.resolve("data"));
								
								this.agent.addEventListener(this);
								
								this.agentStatus = Status.RUN;
							} catch (Exception e) {
								e.printStackTrace();
								
								response.setStatus(Response.Status.SERVERERROR);
							}
						}
					} else {
						response.setStatus(Response.Status.UNAVAILABLE);
					}
					
					return;
				}
				else if (this.agentStatus == Status.READY) {
					response.setStatus(Response.Status.UNAVAILABLE);
					
					return;
				}
			}
			
			switch (command) {
			case "SIGNIN":
				if (session == null) {
					JSONObject account = this.agent.getAccount(data.getString("username"));
					
					if (account == null || !account.getString("password").equals(data.getString("password"))) {
						response.setStatus(Response.Status.UNAUTHORIZED);
					}
					else {
						session = request.getSession();
					
						session.setAttribute("account", account);
						session.setMaxInactiveInterval(SESS_TIMEOUT);
						
						response.write(account.toString());
					}
				}
				else {
					response.write(((JSONObject)session.getAttribute("account")).toString());
				}
				
				break;
				
			case "SIGNOUT":
				if (session != null) {
					session.invalidate();
				}
				
				break;
				
			case "LISTEN":
				if (session == null) {
					response.setStatus(Response.Status.UNAUTHORIZED);
				}
				else {
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
				}
				
				break;
			case "STOP":
				if (session == null) {
					response.setStatus(Response.Status.UNAUTHORIZED);
				}
				else {
					synchronized (this.agentStatus) {
						this.agentStatus = Status.STOP;
					}
					
					this.agent.close();
				}
				
				break;
				
			default:
				if (session == null) {
					response.setStatus(Response.Status.UNAUTHORIZED);
				}
				else if (!parseRequest(command, data, response)) {
					throw new JSONException("Command not found.");
				}
			}
					
		} catch (JSONException | UnsupportedEncodingException e) {
			response.setStatus(Response.Status.BADREQUEST);
			
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
		}
	}
	
	private void setSMTP(JSONObject config) {
		this.smtp = new SMTP(config.getString("smtpServer"),
			config.getString("smtpProtocol"),
			config.getString("smtpUser"),
			config.getString("smtpPassword"));
		
		this.smtp.addEventListener(this);
	}
	
	public void close() {
		synchronized (this.agentStatus) {
			if (this.agentStatus != Status.STOP) {
				this.agentStatus = Status.STOP;
				
				this.agent.close();
			}
		}
		
		try {
			super.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
	
	@Override
	public void onEvent(Object caller, Object ...args) {
		JSONObject event = null;
		
		if (caller instanceof Commander) {
			event = (JSONObject)args[0];
		}
		else if (caller instanceof Expire) {
			System.out.println("Check your License.Expire");
			// TODO 서비스가 시작되기 전에, 서비스 시작 도중에 이벤트 발생하는 경우의 수를 따져서 코드가 꼬이지 않게 종료시켜 주어야 한다.
			close();
		}
		else if (caller instanceof SMTP) {
			//MimeMessage mm = (MimeMessage)args[0];
			//MessagingException me = (MessagingException)args[1];
			
			this.agent.sendEvent(new Event(Event.SYSTEM, 0, Event.WARNING, Lang.WARNING_SMTP_FAIL));
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
						this.smtp.send(Lang.INFO_SMTP_INIT, config.getString("smtpUser"));
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
				.put("path", this.root.toString())
				.put("expire", this.expire);
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
	
	public static void main(String[] args) throws Exception {
		Builder builder = new ITAhM.Builder();
		
		for (int i=0, _i=args.length; i<_i; i++) {
			if (args[i].indexOf("-") != 0) {
				continue;
			}
			
			switch(args[i].substring(1).toUpperCase()) {
			case "ROOT":
				builder.root(args[++i]);
				
				break;
			case "TCP":
				try {
					builder.tcp = Integer.parseInt(args[++i]);
				}
				catch (NumberFormatException nfe) {}
				
				break;
			}
		}
				
		ITAhM itahm = builder
				//.license("A402B93D8051")
				.build();
		
		Runtime.getRuntime().addShutdownHook(
			new Thread() {
				
				@Override
				public void run() {
					if (itahm != null) {
						itahm.close();
					}
				}
			}
		);
	}
}
