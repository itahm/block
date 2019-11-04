package com.itahm.smtp;

import java.io.Closeable;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class SMTP extends Authenticator implements Runnable, Closeable {

	public enum Protocol {
		TLS, SSL
	}
	
	private final Thread thread = new Thread(this, "SMTP Server");
	private final BlockingQueue<MimeMessage> queue = new LinkedBlockingQueue<>();
	private Boolean isClosed = false;
	private Boolean isEnabled = false;
	private Properties props;
	private String user;
	private String password;
	private boolean auth;
	
	public SMTP() {
		thread.setDaemon(true);
		thread.start();
	}
	
	public void disable() {
		synchronized (this.isEnabled) {
			if (this.isEnabled) {
				this.isEnabled = false;
			}
		}
	}
	
	public void enable(String server, String protocol, final String user, final String password) {
		synchronized (this.isEnabled) {
			if (!this.isEnabled) {
				this.isEnabled = true;
			}
			this.props = System.getProperties();
			this.user = user;
			this.password = password;
			
			this.props.put("mail.smtp.host", server);
			//this.props.put("mail.smtp.timeout", TIMEOUT);
			switch (protocol.toUpperCase()) {
				case "SSL":
					this.props.put("mail.smtp.port", "465");
					this.props.put("mail.smtp.socketFactory.port", "465");
					this.props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
					this.props.put("mail.smtp.auth", "true");
					this.auth = true;
					
					break;
				case "TLS":
					this.props.put("mail.smtp.port", "587");
					this.props.put("mail.smtp.starttls.enable", "true");
					this.props.put("mail.smtp.auth", "true");
					
					this.auth = true;
					
					break;
				default:
					this.auth = false;
			}
		}
	}
	
	synchronized public void send(String title, String... to) throws MessagingException {
		synchronized (this.isEnabled) {
			if (!this.isEnabled) {
				return;
			}
		
			MimeMessage mm = new MimeMessage(Session.getInstance(this.props, this.auth? this: null));
			
			mm.addHeader("Content-type", "text/HTML; charset=UTF-8");
			mm.addHeader("format", "flowed");
			mm.addHeader("Content-Transfer-Encoding", "8bit");
			
			mm.setSentDate(new Date());
			
			mm.setSubject(title, "UTF-8");
			mm.setFrom(new InternetAddress(this.user));
			mm.setText("", "UTF-8");
			
			for (String s : to) {
				mm.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(s, false));
			}
			
			this.queue.offer(mm);
		}
	}
	
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication(this.user, this.password);
	}
	
	@Override
	public void close() throws IOException {
		synchronized(this.isClosed) {
			this.isClosed = true;
			
			this.queue.offer(new MimeMessage(Session.getInstance(this.props)));
		}
	}

	@Override
	public void run() {
		MimeMessage mm = null;
		
		while (!this.thread.isInterrupted()) {
			try {
				try {
					mm = this.queue.take();
					
					synchronized(this.isClosed) {
						if (this.isClosed) {
							break;
						}
					}
					
					Transport.send(mm);
				} catch (MessagingException me) {
					me.printStackTrace();
				}
			} catch (InterruptedException ie) {
				break;
			}
		}
	}
	
}
