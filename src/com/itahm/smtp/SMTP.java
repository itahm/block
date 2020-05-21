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
	private long failureCount = 0;
	private long successCount = 0;
	
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
	
	public boolean enable(String server, String protocol, final String user, final String password) {
			Properties props = System.getProperties();
			Authenticator auth = null;
			
			props.put("mail.smtp.host", server);
			props.put("mail.smtp.timeout", 5 * 1000);
			
			switch (protocol.toUpperCase()) {
				case "SSL":
					props.put("mail.smtp.port", "465");
					props.put("mail.smtp.socketFactory.port", "465");
					props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
					props.put("mail.smtp.auth", "true");
					
					auth = new Authenticator() {
						@Override
						protected PasswordAuthentication getPasswordAuthentication() {
							return new PasswordAuthentication(user, password);
						}
					};
					
					break;
				case "TLS":
					props.put("mail.smtp.port", "587");
					props.put("mail.smtp.starttls.enable", "true");
					props.put("mail.smtp.auth", "true");
					
					auth = new Authenticator() {
						@Override
						protected PasswordAuthentication getPasswordAuthentication() {
							return new PasswordAuthentication(user, password);
						}
					};
					
					break;
			}
			
			try {
				MimeMessage mm = createMessage(new MimeMessage(Session.getInstance(props, auth)), user, "NMS Message connected.");
				
				mm.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(user, false));
				
				Transport.send(mm);
				
				synchronized (this.isEnabled) {
					this.isEnabled = true;
				
					this.props = props;
					this.user = user;
					this.password = password;
					
					return true;
				}
			} catch (MessagingException me) {
				me.printStackTrace();
			}
			
			synchronized (this.isEnabled) {
				this.isEnabled = false;
				
				return false;
			}
	}
	
	synchronized public void send(String subject, String... to) {
		synchronized (this.isEnabled) {
			if (!this.isEnabled) {
				return;
			}
		
			try {
				MimeMessage mm = createMessage(new MimeMessage(Session.getInstance(this.props, this)), this.user, subject);
				
				for (String s : to) {
					mm.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(s, false));
				}
				
				this.queue.offer(mm);
			} catch (MessagingException me) {
				me.printStackTrace();
				
				this.failureCount++;
			}
		}
	}
	
	private MimeMessage createMessage(MimeMessage mm, String user, String subject) throws MessagingException {
		mm.setSubject(subject, "UTF-8");
		mm.addHeader("Content-type", "text/HTML; charset=UTF-8");
		mm.addHeader("format", "flowed");
		mm.addHeader("Content-Transfer-Encoding", "8bit");
		mm.setSentDate(new Date());
		mm.setFrom(new InternetAddress(user));
		mm.setText("", "UTF-8");
		
		return mm;
	}
	
	public long getCount(boolean success) {
		return success? this.successCount: this.failureCount;
	}
	
	public boolean isRunning() {
		synchronized (this.isEnabled) {
			return this.isEnabled;
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
					
					this.successCount++;
				} catch (MessagingException me) {
					me.printStackTrace();
					
					this.failureCount++;
				}
			} catch (InterruptedException ie) {
				break;
			}
		}
	}
	
}
