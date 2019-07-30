package com.itahm.block.node;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

abstract public class SNMPNode<T extends Address> extends ICMPNode implements Closeable {

	private final Snmp snmp;
	protected final Target<T> target;
	private final ArrayList<OID> request = new ArrayList<>();
	
	public SNMPNode(Snmp snmp, long id, String ip, Target<T> target) throws IOException {
		super(id, ip);

		super.thread.setName(String.format("SNMPNode %s", ip));
		
		this.snmp = snmp;
		this.target = target;
	}
	
	public synchronized int sendRequest(PDU pdu) throws IOException {
		this.request.clear();

		List<? extends VariableBinding> vbs = pdu.getVariableBindings();
		VariableBinding vb;
		
		for (int i=0, length = vbs.size(); i<length; i++) {
			vb = (VariableBinding)vbs.get(i);
			
			this.request.add(vb.getOid());
		}
		
		return onEvent(this.snmp.send(pdu, this.target));
	}
	
	// recursive method
	private int onEvent(ResponseEvent<T> event) throws IOException {
		if (event == null) {
			return SnmpConstants.SNMP_ERROR_TIMEOUT;
		}
		
		PDU response = event.getResponse();
		
		if (response == null || event.getSource() instanceof Snmp.ReportHandler) {			
			return SnmpConstants.SNMP_ERROR_TIMEOUT;
		}
		
		PDU request = event.getRequest();
		int status = response.getErrorStatus();
		
		if (status != SnmpConstants.SNMP_ERROR_SUCCESS) {
			return status;
		}
		
		PDU nextPDU = getNextPDU(request, response);
		
		if (nextPDU == null) {
			return SnmpConstants.SNMP_ERROR_SUCCESS;
		}
		
		return onEvent(this.snmp.send(nextPDU, this.target));
	}
	
	private final PDU getNextPDU(PDU request, PDU response) throws IOException {
		PDU pdu = null;
		List<? extends VariableBinding> responseVBs = response.getVariableBindings();
		List<VariableBinding> nextRequests = new Vector<VariableBinding>();
		VariableBinding responseVB;
		Variable value;
		OID responseOID;
		
		for (int i=0, length = responseVBs.size(); i<length; i++) {

			responseVB = (VariableBinding)responseVBs.get(i);
			responseOID = responseVB.getOid();
			value = responseVB.getVariable();
			
			if (value == Null.endOfMibView) {
				continue;
			}
			
			for (OID oid : this.request) {
				if (responseOID.startsWith(oid)) {
					
					nextRequests.add(new VariableBinding(responseOID));
					
					super.fireEvent(Event.RESOURCE, oid, responseOID.getSuffix(oid), responseVB.getVariable());
					
					break;
				}
			}
			
			
		}
		
		if (nextRequests.size() > 0) {
			pdu = createPDU();
			
			pdu.setVariableBindings(nextRequests);
		}
		
		return pdu;
	}
	
	abstract protected PDU createPDU();
}