/*
  * JBoss, Home of Professional Open Source
  * Copyright 2007, JBoss Inc., and individual contributors as indicated
  * by the @authors tag. See the copyright.txt in the distribution for a
  * full listing of individual contributors.
  *
  * This is free software; you can redistribute it and/or modify it
  * under the terms of the GNU Lesser General Public License as
  * published by the Free Software Foundation; either version 2.1 of
  * the License, or (at your option) any later version.
  *
  * This software is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this software; if not, write to the Free
  * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
  * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
  */
package org.jboss.test.security.xacml.interop.rsaconf;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

import org.jboss.security.xacml.core.model.context.ActionType;
import org.jboss.security.xacml.core.model.context.RequestType;
import org.jboss.security.xacml.core.model.context.ResourceType;
import org.jboss.security.xacml.core.model.context.SubjectType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.jboss.security.xacml.factories.RequestResponseContextFactory;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;

/**
 * Utility for creating requests for the RSA conference.
 * 
 * @author Marcus Moyses
 * @since Mar 17, 2008
 */
public class Util
{
   private static final String CONFIDENTIALITY_CODE = "urn:xacml:2.0:interop:example:resource:hl7:confidentiality-code";

   private static final String CONSENTED_SUBJECT_ID = "urn:oasis:names:tc:xacml:interop:resource:consented-subject-id";

   private static final String RESOURCE_TYPE = "urn:oasis:names:tc:xacml:interop:resource:type";
   
   public static final String PERMISSION_BASE = "urn:xacml:2.0:interop:example:hl7:";
   
   public static final String PHYSICIAN = "urn:xacml:2.0:interop:example:role:hl7:physician";
   
   public static final String MEDICAL_RECORD = "urn:xacml:2.0:interop:example:resource:hl7:medical-record";

   //Enable for request trace
   private static boolean debug = "true".equals(System.getProperty("debug", "false"));

   /**
    * 
    * Creates a request with the normal XACML concept of roles.
    * 
    * @param principal <code>Principal</code> of the request. Will be the subject-id of the request.
    * @param roles <code>List</code> of roles the subject has.
    * @param resourceId Patient name. Will be the resource-id of the request.
    * @param confidentialityCodes <code>List</code> of confidentiality codes set for the resource.
    * @param consentedIds <code>List</code> of consented subject ids.
    * @param resourceType The resource type.
    * 
    * @return a <code>RequestContext</code> with the <code>RequestType</code> set.
    */
   public static RequestContext createRequestWithNormalRoles(Principal principal, List<String> roles,
         String resourceId, List<String> confidentialityCodes, List<String> consentedIds, String resourceType)
   {
      RequestContext request = RequestResponseContextFactory.createRequestCtx();

      RequestType requestType = createRequestType(principal, resourceId, confidentialityCodes, consentedIds,
            resourceType);
      addNormalRoles(roles, requestType);

      try
      {
         request.setRequest(requestType);
         if (debug)
            request.marshall(System.out);
      }
      catch (IOException e)
      {
      }

      return request;
   }

   /**
    * 
    * Creates a request with the HL7 permission concept of roles..
    * 
    * @param principal <code>Principal</code> of the request. Will be the subject-id of the request.
    * @param permissions <code>List</code> of permissions the subject has.
    * @param resourceId Patient name. Will be the resource-id of the request.
    * @param confidentialityCodes <code>List</code> of confidentiality codes set for the resource.
    * @param consentedIds <code>List</code> of consented subject ids.
    * @param resourceType The resource type.
    * 
    * @return a <code>RequestContext</code> with the <code>RequestType</code> set.
    */
   public static RequestContext createRequestWithHL7Permissions(Principal principal, List<String> permissions,
         String resourceId, List<String> confidentialityCodes, List<String> consentedIds, String resourceType)
   {
      RequestContext request = RequestResponseContextFactory.createRequestCtx();

      RequestType requestType = createRequestType(principal, resourceId, confidentialityCodes, consentedIds,
            resourceType);
      addHL7Permissions(permissions, requestType);

      try
      {
         request.setRequest(requestType);
         if (debug)
            request.marshall(System.out);
      }
      catch (IOException e)
      {
      }

      return request;
   }

   /**
    * 
    * Creates the XACML representation of a request.
    * 
    * @param principal <code>Principal</code> of the request. Will be the subject-id of the request.
    * @param resourceId Patient name. Will be the resource-id of the request.
    * @param confidentialityCodes <code>List</code> of confidentiality codes set for the resource.
    * @param consentedIds <code>List</code> of consented subject ids.
    * @param resourceType The resource type.
    * 
    * @return a <code>RequestType</code> representing the XACML request.
    */
   public static RequestType createRequestType(Principal principal, String resourceId,
         List<String> confidentialityCodes, List<String> consentedIds, String resourceType)
   {
      RequestType requestType = new RequestType();

      //create the Subject of the request
      SubjectType subject = new SubjectType();
      subject.getAttribute().add(
            RequestAttributeFactory.createStringAttributeType(XACMLConstants.ATTRIBUTEID_SUBJECT_ID, null, principal
                  .getName()));
      requestType.getSubject().add(subject);

      //create the Resource of the request
      ResourceType resource = new ResourceType();
      resource.getAttribute()
            .add(
                  RequestAttributeFactory.createStringAttributeType(XACMLConstants.ATTRIBUTEID_RESOURCE_ID, null,
                        resourceId));
      for (String confidentialityCode : confidentialityCodes)
      {
         resource.getAttribute().add(
               RequestAttributeFactory.createStringAttributeType(CONFIDENTIALITY_CODE, null, confidentialityCode));
      }
      for (String consentedId : consentedIds)
      {
         resource.getAttribute().add(
               RequestAttributeFactory.createStringAttributeType(CONSENTED_SUBJECT_ID, null, consentedId));
      }
      resource.getAttribute().add(RequestAttributeFactory.createStringAttributeType(RESOURCE_TYPE, null, resourceType));
      requestType.getResource().add(resource);

      //create the Action of the request - avoid NPE
      requestType.setAction(new ActionType());

      //      requestType.setEnvironment(new EnvironmentType());

      return requestType;
   }

   /**
    * 
    * Adds normal XACML roles to the request's subject.
    * 
    * @param roles <code>List</code> of roles the subject has.
    * @param request a XACML request.
    */
   public static void addNormalRoles(List<String> roles, RequestType request)
   {
      SubjectType subject = request.getSubject().iterator().next();
      if (subject != null)
      {
         for (String role : roles)
         {
            subject.getAttribute().add(
                  RequestAttributeFactory.createStringAttributeType(XACMLConstants.ATTRIBUTEID_ROLE, null, role));
         }
      }
   }

   /**
    * 
    * Adds HL7 permissions to the request's subject.
    * 
    * @param permissions <code>List</code> of permissions the subject has.
    * @param request a XACML request.
    */
   public static void addHL7Permissions(List<String> permissions, RequestType request)
   {
      SubjectType subject = request.getSubject().iterator().next();
      if (subject != null)
      {
         for (String permission : permissions)
         {
            subject.getAttribute().add(
                  RequestAttributeFactory.createStringAttributeType(XACMLConstants.ATTRIBUTEID_HL7_PERMISSION, null,
                        permission));
         }
      }
   }

}
