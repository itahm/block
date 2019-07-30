package com.itahm;

import java.io.IOException;
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
	
	private final Path root;
	public final int limit;
	private Agent agent;
	private SMTP smtp;
	
	private ITAhM(Builder builder) throws Exception {
		super(builder.ip, builder.tcp);
		
		System.out.format("ITAhM HTTP Server started with TCP %d.\n", builder.tcp);
		
		root = builder.root;
		limit = builder.limit;
		
		if (builder.expire > 0 && new Expire(builder.expire, this).isExpired()) {
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
		private long expire = -1;
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
			case "SET":
				set(request, response);
				
				break;
			case "REMOVE":
				remove(request, response);
				
				break;
			case "GET":
				get(request, response);
				
				break;
			case "QUERY":
				this.agent.getDataByID(request.getString("key"));
				
				break;
			case "SEARCH":
				this.agent.search(request.getString("network"), request.getInt("mask"));
				
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
			
			response.setStatus(Response.Status.SERVERERROR);
		}
		
		return true;
	}
	
	private void add(JSONObject request, Response response) {
		boolean success = true;
		
		switch(request.getString("target").toUpperCase()) {
		case "ACCOUNT":
			success = this.agent.addAccount(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "ICON":
			success = this.agent.addIcon(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "LINE":
			this.agent.addLine(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "NODE":
			this.agent.addNode(request.getJSONObject("value"));
			
			break;
		case "PROFILE":
			this.agent.addProfile(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "USER":
			this.agent.addUser(request.getString("key"), request.getJSONObject("value"));
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
		
		if (!success) {
			// response status 정해줄것
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
		case "LINE":
			success = this.agent.setLine(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "MONOTOR":
			success = this.agent.setMonitor(request.getLong("key"), request.getString("value"));
			
			break;
		case "NODE":
			success = this.agent.setNode(request.getLong("key"), request.getJSONObject("value"));
			
			break;
		case "POSITION":
			success = this.agent.setPosition(request.getString("key"), request.getJSONObject("value"));
			
			break;
		case "SETTING":
			success = this.agent.setSetting(request.getString("key"), request.getString("value"));
			
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
			success = this.agent.removeAccount(request.getString("key"));
			
			break;
		case "ICON":
			success = this.agent.removeIcon(request.getString("key"));
			
			break;
		case "LINE":
			success = this.agent.removeLine(request.getString("key"));
			
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
			
			for (int i=0, _i=targets.length(); i<_i; i++) {
				get(targets.getString(i), request, response);
			}
		}
		else if (target instanceof String){
			if (request.has("key")) {
				get((String)target, request.get("key"), request, response);	
			}
			else {
				get((String)target, request, response);
			}
		}
	}
	
	private void get(String target, Object o, JSONObject request, Response response) {
		if (o instanceof String) {
			String key = (String)o;
		
			switch(target.toUpperCase()) {
			case "NODE":
				this.agent.getNodeByID(key, request.has("snmp") && request.getBoolean("snmp"));
				
				break;
			case "LOG":
				this.agent.getEventByDate(Long.valueOf(key));
				
				break;
			case "ICON":
				this.agent.getIconByType(key);
				
				break;
			case "SETTING":
				this.agent.getSettingByKey(key);
				
				break;
			default:
				
				throw new JSONException("Target is not found.");
			}
		}
		else if (o instanceof JSONObject && target.equalsIgnoreCase("TRAFFIC")) {
			switch(target.toUpperCase()) {
			case "TRAFFIC":
				this.agent.getTraffic((JSONObject)o);
				
				break;
			case "TOP":
				this.agent.getTop((JSONObject)o);
				
				break;
			default:
				
				throw new JSONException("Target is not found.");
			}
		}
		else {
			throw new JSONException("Target is not found.");
		}
	}
	
	private void get(String target, JSONObject request, Response response) {
		JSONObject result;
		
		switch(target.toUpperCase()) {
		case "ACCOUNT":
			result = this.agent.getAccountAll();
			
			break;
		case "INFORMATION":
			result = this.agent.getInformation();
			
			try {
				result
					.put("java", System.getProperty("java.version"))
					.put("space", Files.getFileStore(this.root).getUsableSpace());
			} catch (IOException ioe) {
				System.out.print(ioe);
			}
			
			break;
		case "LINE":
			result = this.agent.getLineAll();
			
			break;
		case "NODE":
			result = this.agent.getNodeAll();
			
			break;
		case "POSITION":
			result = this.agent.getPositionByName("position");
			
			break;
		case "profile":
			result = this.agent.getProfileAll();
			
			break;
		case "SETTING":
			result = this.agent.getSettingAll();
			
			break;
		default:
			
			throw new JSONException("Target is not found.");
		}
		
		response.write(result.toString());
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
				.license("A402B93D8051")
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
