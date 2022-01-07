package org.apache.directory.server.ldap.handlers.request;

import java.util.Map;

import org.apache.directory.api.ldap.model.message.AbstractRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;

public class MyVDExtendedRequest extends AbstractRequest implements ExtendedRequest {

    protected MyVDExtendedRequest(int id, MessageTypeEnum type, boolean hasResponse) {
        super(id, type, hasResponse);
        //TODO Auto-generated constructor stub
    }

    @Override
    public MessageTypeEnum getResponseType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ResultResponse getResultResponse() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getRequestName() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ExtendedRequest setRequestName(String oid) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ExtendedRequest setMessageId(int messageId) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ExtendedRequest addControl(Control control) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ExtendedRequest addAllControls(Control[] controls) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ExtendedRequest removeControl(Control control) {
        // TODO Auto-generated method stub
        return null;
    }

    
    
}
