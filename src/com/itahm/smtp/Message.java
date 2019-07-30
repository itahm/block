package com.itahm.smtp;

import java.util.Date;
import java.util.Properties;

import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

public class Message {

	private final static String TIMEOUT = "5000";
	
	private final Properties props = System.getProperties();
	private MimeMessage message;
	
	public static Message getInstance(String server, String user) {
		Message message = new Message();
		
		try {
			message.createMessage(server);
			message.set(user);
			
			return message;
		} catch (MessagingException me) {
			System.err.print(me);
		}
		
		return null;
	}
	
	public static Message getTLSInstance(String server, String user, String password) {
		Message message = new Message();
		
		try {
			message.createTLSMessage(server, user, password);
			message.set(user);
			
			return message;
		} catch (MessagingException me) {
			System.err.print(me);
		}
		
		return null;
	}
	
	public static Message getSSLInstance(String server, String user, String password) {
		Message message = new Message();
		
		try {
			message.createSSLMessage(server, user, password);
			message.set(user);
			
			return message;
		} catch (MessagingException me) {
			System.err.print(me);
		}
		
		return null;
	}
	
	private void createMessage(String server) throws MessagingException {
		this.props.put("mail.smtp.host", server);
		this.props.put("mail.smtp.timeout", TIMEOUT);
		
		this.message = new MimeMessage(Session.getInstance(props, null));
	}
	
	private void createTLSMessage(String server, String user, String password) throws MessagingException {
		this.props.put("mail.smtp.host", server);
		this.props.put("mail.smtp.timeout", TIMEOUT);
		this.props.put("mail.smtp.auth", "true");
		
		this.props.put("mail.smtp.port", "587");
		
		this.props.put("mail.smtp.starttls.enable", "true");
		
		this.message = new MimeMessage(Session.getInstance(props, new Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(user, password);
			}
		}));
	}
	
	private void createSSLMessage(String server, String user, String password) throws MessagingException {
		this.props.put("mail.smtp.host", server);
		this.props.put("mail.smtp.timeout", TIMEOUT);
		this.props.put("mail.smtp.auth", "true");
		
		this.props.put("mail.smtp.port", "465");
		
		this.props.put("mail.smtp.socketFactory.port", "465");
		this.props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		
		this.message = new MimeMessage(Session.getInstance(props, new Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(user, password);
			}
		}));
	}
	
	private void set(String user) throws MessagingException {
		this.message.addHeader("Content-type", "text/HTML; charset=UTF-8");
		this.message.addHeader("format", "flowed");
		this.message.addHeader("Content-Transfer-Encoding", "8bit");
		
		this.message.setSentDate(new Date());
		
		this.message.setFrom(new InternetAddress(user));
	}
	
	public Message title(String subject) {
		try {
			this.message.setSubject(subject, "UTF-8");
		} catch (MessagingException me) {
			System.err.print(me);
		}
		
		return this;
	}
	
	public Message body(String body) {
		try {
			this.message.setText(body, "UTF-8");
		} catch (MessagingException me) {
			System.err.print(me);
		}
		
		return this;
	}
	
	public Message to(String to) throws MessagingException {
		this.message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(to, false));
		
		return this;
	}
	
	public Message to(String [] to) throws MessagingException {
		for (String s : to) {
			this.message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(s, false));
		}
		
		return this;
	}
	
	public void send() throws MessagingException {
		Transport.send(this.message);
	}
	
	public static void main(String ...args) throws MessagingException {
		Message.getTLSInstance("smtp.daum.net", "tomato322@daum.net", "2014@ITAhM.com").title("test").body("good").to("tomato322@daum.net").send();
	}
}
