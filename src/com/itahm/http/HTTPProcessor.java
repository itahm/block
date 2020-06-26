package com.itahm.http;

import java.io.IOException;

import com.itahm.http.Connection.Header;

public class HTTPProcessor extends Thread {
	
	private final HTTPServer server;
	private final Connection connection;
	private final Request request;
	
	public HTTPProcessor(HTTPServer server, Connection connection) {
		this.server = server;
		this.connection = connection;
		
		request = connection.createRequest();
		
		setDaemon(true);
		setName("ITAhM HTTPProcessor");
		
		start();
	}
	
	@Override
	public void run() {
		Response response = new Response();
		String origin = request.getHeader(Header.ORIGIN.toString());
		
		switch(this.request.getMethod().toUpperCase()) {
		case "GET":
			this.server.doGet(this.request, response);
			
			break;
		case "OPTIONS":			
			if (origin != null) {
				response.setHeader("Access-Control-Allow-Credentials", "true");
				response.setHeader("Access-Control-Allow-Origin", origin);
				response.setHeader("Access-Control-Allow-Methods","POST, GET, PUT, OPTIONS");
				response.setHeader("Access-Control-Allow-Headers", "Session, File-Target, File-Id");
			}
			
			break;
		case "POST":
			if (origin != null) {
				response.setHeader("Access-Control-Allow-Credentials", "true");
				response.setHeader("Access-Control-Allow-Origin", origin);
			}
			
			this.server.doPost(this.request, response);
			
			break;
		case "PUT":
			if (origin != null) {
				response.setHeader("Access-Control-Allow-Credentials", "true");
				response.setHeader("Access-Control-Allow-Origin", origin);
			}
			
			this.server.doPut(this.request, response);
			
			break;
		default:
			response.setStatus(Response.Status.NOTALLOWED);
			response.setHeader("Allow", "GET POST OPTIONS");
		}
		
		Session session = this.request.getSession(false);
		
		if (session != null) {
			if (!session.id.equals(request.getRequestedSessionId())) {
				response.setHeader("Access-Control-Expose-Headers", "Set-Session");
				response.setHeader("Set-Session", session.id);
			}
		}
		
		try {
			this.connection.write(response);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}
