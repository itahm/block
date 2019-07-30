package com.itahm.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;

public class Util {

	public static void download(URL url, File file) throws IOException {
		try (BufferedInputStream bi = new BufferedInputStream(url.openStream());
			FileOutputStream fos = new FileOutputStream(file);
		) {
			final byte buffer[] = new byte[1024];
			int length;
			
			while ((length = bi.read(buffer, 0, 1024)) != -1) {
				fos.write(buffer,  0, length);
			}
		}
	}
	
	public static Object loadClass(URL url, String name) throws InstantiationException, IllegalAccessException, ClassNotFoundException, IOException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
		try (URLClassLoader urlcl = new URLClassLoader(new URL [] {
				url
			})) {
			
			return urlcl.loadClass(name).getDeclaredConstructor().newInstance();
		}
	}
	
	public static String EToString(Exception e) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);

		e.printStackTrace(pw);
		
		return sw.toString();
	}
	
	public static Calendar trimDate(Calendar c) {
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		
		return c;
	}

	public static String toDateString(Date date) {
		Calendar c = Calendar.getInstance();
		
		c.setTime(date);
		
		return String.format("%04d-%02d-%02d %02d:%02d:%02d"
			, c.get(Calendar.YEAR)
			, c.get(Calendar.MONTH +1)
			, c.get(Calendar.DAY_OF_MONTH)
			, c.get(Calendar.HOUR_OF_DAY)
			, c.get(Calendar.MINUTE)
			, c.get(Calendar.SECOND));
	}
	
	public static long getDateInMillis() {
		Calendar c = Calendar.getInstance();
		
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
	
		return c.getTimeInMillis();
	}
	
	/**
	 * 
	 * @param file
	 * @return null if not json file
	 * @throws IOException
	 */
	public static JSONObject getJSONFromFile(File file) throws IOException {
		try {
			return new JSONObject(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
		}
		catch (JSONException jsone) {
			return null;
		}
	}
	
	public static JSONObject getJSONFromFile(Path path) throws IOException {
		try {
			return new JSONObject(new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
		}
		catch (JSONException jsone) {
			return null;
		}
	}
	
	/**
	 * 
	 * @param file destination
	 * @param json source
	 * @return source itself
	 * @throws IOException
	 */
	public static JSONObject putJSONtoFile(File file, JSONObject json) throws IOException {
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(json.toString().getBytes(StandardCharsets.UTF_8));
		}
		
		return json;
	}
	
	public static void putJSONtoFile(Path path, JSONObject json) throws IOException {
		Files.write(path, json.toString().getBytes(StandardCharsets.UTF_8));
	}
	
	public final static long getDirectorySize(Path parent, String fileName) throws IOException {
		Path path = parent.resolve(fileName);
		long size = 0;
		
		if (Files.isDirectory(path)) {
			for (Path file : Files.newDirectoryStream(path)) {
				if (Files.isRegularFile(file)) {
					size += Files.size(file);
				}
			}
		}
		else if (Files.isDirectory(parent)) {
			for (Path file : Files.newDirectoryStream(parent)) {
				size += getDirectorySize(file, fileName);
			}
		}
		
		return size;
	}
	
	public final static void deleteDirectory(File directory) {
		File[] files = directory.listFiles();
		
		if (files != null) {
			for (File file : files) {
				deleteDirectory(file);
			}
		}
		
		directory.delete();
	}
	
	public final static String toValidString(byte [] ba) {
		try {
			return Charset
				.forName(StandardCharsets.UTF_8.name())
				.newDecoder()
				.decode(ByteBuffer.wrap(ba))
				.toString();
		}
		catch (CharacterCodingException cce) {
			try {
				return new String(ba, "EUC-KR");
			} catch (UnsupportedEncodingException uee) {
				return new String(ba);
			}
		}
	}
	
	public final static boolean isValidAddress(byte [] mac) {
		Enumeration<NetworkInterface> e;
		
		try {
			e = NetworkInterface.getNetworkInterfaces();
		
			NetworkInterface ni;
			byte [] ba;
			
			while(e.hasMoreElements()) {
				ni = e.nextElement();
				
				if (ni.isUp() && !ni.isLoopback() && !ni.isVirtual()) {
					 ba = ni.getHardwareAddress();
					 
					 if(ba!= null) {
						 if (Arrays.equals(mac, ba)) {
							 return true; 
						 }
					 }
				}
			}
		} catch (SocketException se) {
		}
		
		return false;
	}
	
	public final static boolean isValidAddress(String mac) {
		try {
			long l = Long.parseLong(mac, 16);
			byte [] ba = new byte[6];
			
			for (int i=6; i>0; l>>=8) {
				ba[--i] = (byte)(0xff & l);
			}
			
			return isValidAddress(ba);
				
		} catch (NumberFormatException nfe) {}
		
		return false;
	}
	
}