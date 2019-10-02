package com.itahm.smtp;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
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

import com.itahm.util.Listener;

public class SMTP extends Authenticator implements Runnable, Closeable {

	public enum Protocol {
		TLS, SSL
	}
	
	private final Thread thread = new Thread(this, "SMTP Server");
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	private final Properties props = System.getProperties();
	private final BlockingQueue<MimeMessage> queue = new LinkedBlockingQueue<>();
	private Boolean isClosed = false;
	private final String user;
	private final String password;
	private final Protocol protocol;
	
	public SMTP(String server, String user) {
		this(server, user, null, null);
	}
	
	public SMTP(String server, final String user, final String password, Protocol protocol) {
		this.user = user;
		this.password = password;
		this.protocol = protocol;
		
		props.put("mail.smtp.host", server);
		//props.put("mail.smtp.timeout", TIMEOUT);
		
		if (protocol != null) {
			props.put("mail.smtp.auth", "true");
			
			switch (protocol) {
			case SSL:
				props.put("mail.smtp.port", "465");
				props.put("mail.smtp.socketFactory.port", "465");
				props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
				
				break;
			case TLS:
				props.put("mail.smtp.port", "587");
				props.put("mail.smtp.starttls.enable", "true");
				
				break;
			}
		}
		
		thread.setDaemon(true);
		thread.start();
	}
	
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);
	}
	
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}
	
	//public void send(String title, String body, String... to) throws MessagingException {
	public void send(String title, String... to) throws MessagingException {
		MimeMessage mm = new MimeMessage(Session.getInstance(this.props, this.protocol == null? null: this));
		
		mm.addHeader("Content-type", "text/HTML; charset=UTF-8");
		mm.addHeader("format", "flowed");
		mm.addHeader("Content-Transfer-Encoding", "8bit");
		
		mm.setSentDate(new Date());
		
		mm.setSubject(title, "UTF-8");
		mm.setFrom(new InternetAddress(this.user));
		//mm.setText(body, "UTF-8");
		
		for (String s : to) {
			mm.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(s, false));
		}
		
		this.queue.offer(mm);
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
		MimeMessage mm;
		
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
					for (Listener l :this.listenerList) {
						l.onEvent(this, me);
					}
				}
			} catch (InterruptedException ie) {
				break;
			}
		}
	}
	
}
