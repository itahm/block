package com.itahm.nms.parser;

public class IFOutErrors extends IFErrors {
	
	private final static String ERRORS_OID = "1.3.6.1.2.1.2.2.1.20";
	private final static String CPS_OID = "1.3.6.1.4.1.49447.3.4";
	private final static String EVENT_TITLE = "송신 오류";

	@Override
	protected String getErrorsOID() {
		return ERRORS_OID;
	}

	@Override
	protected String getCPSOID() {
		return CPS_OID;
	}

	@Override
	protected String getEventTitle() {
		return EVENT_TITLE;
	}
	
	@Override
	public String toString() {
		return "IFOUTERRORS";
	}
}
