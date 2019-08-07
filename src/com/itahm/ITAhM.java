package com.itahm;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.regex.Pattern;

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
import com.itahm.block.Agent;
import com.itahm.block.SMTP;

public class ITAhM extends HTTPServer implements Listener {
	private byte [] event = null;
	private final static int SESS_TIMEOUT = 3600;
	private final static String VERSION = "CeMS v1.0"; 
	private final Path root;
	public final int limit;
	public final long expire;
	private Agent agent;
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
		
		agent = new Agent(root.resolve("data"));
		
		agent.addEventListener(this);
		
		// TODO sms, app 을 위한 리스너 등록
		//agent.addEventListener();
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
		
		if (agent == null) {
			response.setStatus(Response.Status.UNAVAILABLE);
			
			return;
		}
		
		JSONObject data;
		
		try {
			data = new JSONObject(new String(request.read(), StandardCharsets.UTF_8.name()));
			
			if (!data.has("command")) {
				throw new JSONException("Command not found.");
			}
			
			Session session = request.getSession(false);
			
			switch (data.getString("command").toLowerCase()) {
			case "signin":
				if (session == null) {
					JSONObject account = this.agent.getAccountByUsername(data.getString("username"));
					
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
				
			case "signout":
				if (session != null) {
					session.invalidate();
				}
				
				break;
				
			case "listen":
				if (session == null) {
					response.setStatus(Response.Status.UNAUTHORIZED);
				}
				else {
					JSONObject event = null;
					
					if (data.has("event")) {
						event = this.agent.getEventByID(data.getLong("event"));
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
				
			default:
				if (session == null) {
					response.setStatus(Response.Status.UNAUTHORIZED);
				}
				else if (!parseRequest(data, response)) {
					throw new JSONException("Command not found.");
				}
			}
					
		} catch (JSONException | UnsupportedEncodingException e) {
			response.setStatus(Response.Status.BADREQUEST);
			
			response.write(new JSONObject().
				put("error", e.getMessage()).toString());
		}
	}
	
	public void close() {
		try {
			super.close();
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
	}
	
	@Override
	public void onEvent(Object caller, Object ...event) {
		if (caller instanceof Expire) {
			
		}
		else if (caller instanceof SMTP) {
			
		}
		
		if (event == null) {
			System.out.println("Check your License.Expire");
			// TODO 서비스가 시작되기 전에, 서비스 시작 도중에 이벤트 발생하는 경우의 수를 따져서 코드가 꼬이지 않게 종료시켜 주어야 한다.
			close();
		}
		else {
			synchronized(this) {
				JSONObject e = (JSONObject)event[0];
				
				try {
					this.event = e.toString().getBytes(StandardCharsets.UTF_8.name());
					
					notifyAll();
				} catch (UnsupportedEncodingException uee) {}			
			}
		}
	}
	
	private boolean parseRequest(JSONObject request, Response response) {
		try {
			switch(request.getString("command").toUpperCase()) {
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
			case "QUERY":
				this.agent.getDataByID(request.getLong("id"));
				
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
			System.out.println(e.getMessage());
			System.err.print(e);
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
			success = this.agent.addIcon(request.getString("type"), request.getJSONObject("icon"));
			
			break;
		case "LINK":
			if (!this.agent.addLink(request.getLong("nodeFrom"), request.getLong("nodeTo"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			break;
			
		case "NODE":
			if (this.agent.addNode(request.getJSONObject("node")) == null) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PATH":
			if (!this.agent.addPath(request.getLong("nodeFrom"), request.getLong("nodeTo"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PROFILE":
			this.agent.addProfile(request.getString("name"), request.getJSONObject("profile"));
			
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
		boolean success = true;
		
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			success = this.agent.setAccount(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "CONFIG":
			switch (request.getString("key")) {
			case "storeDate":
				success = this.agent.setStoreDate(Integer.valueOf(request.getString("value")));
				
				break;
			case "health": 
				success = this.agent.setHealth(Integer.valueOf(request.getString("value")));
				
				break;
			case "saveInterval": 
				success = this.agent.setSaveInterval(Integer.valueOf(request.getString("value")));
				
				break;
			case "smpInterval": 
				success = this.agent.setSNMPInterval(Long.valueOf(request.getString("value")));
				
				break;
			case "snmpServer":
				if (this.smtp != null) {
					try {
						this.smtp.close();
					} catch (IOException ioe) {
						System.err.print(ioe);
					}
				}
				
				this.smtp = this.agent.setSMTPServer(request.get("value").equals(JSONObject.NULL)? null: new JSONObject(request.getJSONObject("value")));
				
				success = true;
				
				break;
			case "topCount": 
				success = this.agent.setTopCount(Integer.valueOf(request.getString("value")));
				
				break;
			default:
				success = false;
			}
			break;
		case "CRITICAL":
			success = this.agent.setCritical(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "ICON":
			success = this.agent.setIcon(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "LINK":
			if (!this.agent.setLink(request.getLong("nodeFrom"), request.getLong("nodeTo"), request.getLong("id"),request.getJSONObject("link"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "PATH":
			if (!this.agent.setPath(request.getLong("nodeFrom"), request.getLong("nodeTo"), request.getJSONObject("path"))) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "MONOTOR":
			success = this.agent.setMonitor(request.getLong("id"), request.getString("protocol"));
			
			break;
		case "NODE":
			if (!this.agent.setNode(request.getLong("key"), request.getJSONObject("value"))) {
				response.setStatus(Response.Status.SERVERERROR);
			}
			
			break;
		case "POSITION":
			success = this.agent.setPosition(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "SETTING":
			if (!this.agent.setSetting(request.getString("key"), request.has("value")? request.getString("value"): null)) {
				response.setStatus(Response.Status.CONFLICT);
			}
			
			break;
		case "SPEED":
			success = this.agent.setCritical(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "UPDOWN":
			success = this.agent.setCritical(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "USER":
			success = this.agent.setUser(request.getString("key"), request.getJSONObject("value"));
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
		
		if (!success) {
			
		}
	}
	
	private void remove(JSONObject request, Response response) {
		boolean success = true;
		
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			success = this.agent.removeAccount(request.getString("username"));
			
			break;
		case "ICON":
			success = this.agent.removeIcon(request.getString("key"));
			
			break;
		case "LINK":
			if (this.agent.removeLink(request.getLong("nodeFrom"), request.getLong("nodeTo"), request.getLong("id")) == null) {
				response.setStatus(Response.Status.CONFLICT);
			};
			
			break;
		case "MONOTOR":
			success = this.agent.removeMonitor(request.getLong("key"));
			
			break;
		case "NODE":
			success = this.agent.removeNode(request.getLong("key"));
			
			break;
		case "PROFILE":
			success = this.agent.removeProfile(request.getString("key"));
			
			break;
		case "USER":
			success = this.agent.removeUser(request.getString("key"));
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
		
		if (!success) {
			
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
			return request.has("username")? this.agent.getAccountByUsername(request.getString("username")): this.agent.getAccount();
		case "CONFIG": return request.has("key")? this.agent.getConfigByKey(request.getString("key")): this.agent.getConfig();
		case "ICON": return request.has("type")? this.agent.getIconByType(request.getString("type")): this.agent.getIcon();
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
				System.err.print(ioe);
			}
			
			return result;
		case "LINK": return request.has("nodeFrom")? this.agent.getLinkByNodeID(request.getLong("nodeFrom"), request.getLong("nodeTo")): this.agent.getLink();
		case "LOG": return this.agent.getEventByDate(request.getLong("date"));
		case "NODE": return request.has("id")? this.agent.getNodeByID(request.getLong("id"), request.has("snmp") && request.getBoolean("snmp")): this.agent.getNode();
		case "PATH":return request.has("nodeFrom")? this.agent.getPathByNodeID(request.getLong("nodeFrom"), request.getLong("nodeTo")): this.agent.getPath();
		case "POSITION": return this.agent.getPositionByName("position");
		case "PROFILE": return this.agent.getProfile();
		case "SETTING": return request.has("key")? this.agent.getSettingByKey(request.getString("key")): this.agent.getSetting();
		case "TOP": return this.agent.getTop(request.getJSONObject("top"));
		case "TRAFFIC": return this.agent.getTraffic(request.getJSONObject("traffic"));
		
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
		
		System.setErr(
			new PrintStream(
				new OutputStream() {

					@Override
					public void write(int b) throws IOException {
					}	
				}
			) {
		
				@Override
				public void print(Object e) {
					((Exception)e).printStackTrace(System.out);
				}
			}
		);
		
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
