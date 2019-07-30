package com.itahm.http;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Response {

	public final static String CRLF = "\r\n";
	public final static String FIELD = "%s: %s"+ CRLF;
	
	private final Map<String, String> header = new HashMap<String, String>();
	private Status status = Status.OK;
	private byte [] body = new byte [0];
	
	public enum Status {
		OK(200, "OK"),
		BADREQUEST(400, "Bad request"),
		UNAUTHORIZED(401, "Unauthorized"),
		NOTFOUND(404, "Not found"),
		NOTALLOWED(405, "Method Not Allowed"),
		CONFLICT(409, "Conflict"),
		SERVERERROR(500, "Internal Server Error"),
		NOTIMPLEMENTED(501, "Not Implemented"),
		UNAVAILABLE(503, "Service Unavailable"),
		VERSIONNOTSUP(505, "HTTP Version Not Supported");
		
		private final int code;
		private final String text;
		
		private Status(int code, String text) {
			this.code = code;
			this.text = text;
		}
		
		public int getCode() {
			return this.code;
		}
		
		public String getText() {
			return this.text;
		}
		
		public static Status valueOf(int code) {
			for (Status status : Status.values()) {
				if (status.getCode() == code) {
					return status;
				}
			}
			
			return null;
		}
	};
	
	public void setStatus(Status status) {
		this.status = status;
	}
	
	public Status getStatus() {
		return this.status;
	}
	
	public void write(byte [] body) {
		this.body = body;
	}
	
	public void write(String body) {
		try {
			this.body = body.getBytes(StandardCharsets.UTF_8.name());
		} catch (UnsupportedEncodingException e) {
			this.body = new byte [0];
		}
	}
	
	public void write(File url) throws IOException {
		write(url.toPath());
	}
	
	public void write(Path url) throws IOException {
		write(Files.readAllBytes(url));
		
		setHeader("Content-type", Files.probeContentType(url));
	}
	
	public byte [] read() {
		return this.body;
	}
	
	public Response setHeader(String name, String value) {
		this.header.put(name, value);
		
		return this;
	}
	
	public ByteBuffer build() throws IOException {
		StringBuilder sb = new StringBuilder();
		Iterator<String> iterator;		
		String key;
		byte [] header;
		byte [] message;
		
		sb.append(String.format("HTTP/1.1 %d %s" +CRLF, this.status.getCode(), this.status.getText()));
		sb.append(String.format(FIELD, "Content-Length", String.valueOf(this.body.length)));
		
		iterator = this.header.keySet().iterator();
		while(iterator.hasNext()) {
			key = iterator.next();
			
			sb.append(String.format(FIELD, key, this.header.get(key)));
		}
		
		sb.append(CRLF);
		
		header = sb.toString().getBytes(StandardCharsets.US_ASCII.name());
		
		message = new byte [header.length + this.body.length];
		
		System.arraycopy(header, 0, message, 0, header.length);
		System.arraycopy(this.body, 0, message, header.length, this.body.length);
		
		return ByteBuffer.wrap(message);
	}
	
}
