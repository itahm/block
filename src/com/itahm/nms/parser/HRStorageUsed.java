package com.itahm.nms.parser;

public class HRStorageUsed extends HRStorage {

	private final static String OID = "1.3.6.1.2.1.25.2.1.4";
	private final static String EVENT_TITLE = "저장 공간";
	
	@Override
	public String getStorageTypeOID() {
		return OID;
	}

	@Override
	protected String getEventTitle() {
		return EVENT_TITLE;
	}
	
}
