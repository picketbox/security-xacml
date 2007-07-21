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
package org.jboss.security.xacml.factories;

import java.net.InetAddress;
import java.net.URI;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.core.model.context.AttributeValueType;

//$Id$

/**
 *  Construct Commonly Used Attributes in Request Subject/Resource/Action
 *  and Environment sections
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class RequestAttributeFactory
{
   
   public static AttributeType createAnyURIAttributeType(String attrID, String issuer,URI value)
   {
      return getBareAttributeType(attrID, issuer, ""+value, "http://www.w3.org/2001/XMLSchema#anyURI");
   }
   
   public static AttributeType createBase64BinaryAttributeType(String attrID, String issuer,byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, "http://www.w3.org/2001/XMLSchema#base64Binary");
   }
   
   public static AttributeType createBooleanAttributeType(String attrID, String issuer,boolean value)
   {
      return getBareAttributeType(attrID, issuer, value, "http://www.w3.org/2001/XMLSchema#boolean");
   }
   
   public static AttributeType createDateAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), "http://www.w3.org/2001/XMLSchema#date");
   }
   
   public static AttributeType createDateAttributeType(String attrID, String issuer,XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), "http://www.w3.org/2001/XMLSchema#date");
   }
   
   public static AttributeType createDateTimeAttributeType(String attrID, String issuer)
   {
      return getBareAttributeType(attrID, issuer, getXMLDate(), "http://www.w3.org/2001/XMLSchema#dateTime");
   }
   
   public static AttributeType createDateTimeAttributeType(String attrID, String issuer,XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), "http://www.w3.org/2001/XMLSchema#dateTime");
   }
   
   public static AttributeType createDNSNameAttributeType(String attrID, String issuer,String hostname)
   {
      return getBareAttributeType(attrID, issuer, hostname, "urn:oasis:names:tc:xacml:2.0:data-type:dnsName");
   }
   
   public static AttributeType createDoubleAttributeType(String attrID, String issuer,double value)
   {
      return getBareAttributeType(attrID, issuer, "" + value, "http://www.w3.org/2001/XMLSchema#double");
   }
   
   public static AttributeType createEmailAttributeType(String attrID, String issuer,String value)
   {
      return getBareAttributeType(attrID, issuer, value, "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name");
   }
   
   public static AttributeType createHexBinaryAttributeType(String attrID, String issuer,byte[] value)
   {
      return getBareAttributeType(attrID, issuer, value, "http://www.w3.org/2001/XMLSchema#hexBinary");
   }
   
   public static AttributeType createIntegerAttributeType(String attrID, String issuer, int value)
   {
     return getBareAttributeType(attrID, issuer, ""+value, "http://www.w3.org/2001/XMLSchema#integer"); 
   }
   
   public static AttributeType createIPAddressAttributeType(String attrID, String issuer,InetAddress address)
   {
      return getBareAttributeType(attrID, issuer, address, "urn:oasis:names:tc:xacml:2.0:data-type:ipAddress"); 
   }
   
   public static AttributeType createStringAttributeType(String attrID, String issuer, String value)
   {
      return getBareAttributeType(attrID, issuer, value, "http://www.w3.org/2001/XMLSchema#string"); 
   }
   
   public static AttributeType createTimeAttributeType(String attrID, String issuer)
   { 
      return getBareAttributeType(attrID, issuer, getXMLDate(), "http://www.w3.org/2001/XMLSchema#time"); 
   }
   
   public static AttributeType createTimeAttributeType(String attrID, String issuer, XMLGregorianCalendar value)
   {
      return getBareAttributeType(attrID, issuer, value.toXMLFormat(), "http://www.w3.org/2001/XMLSchema#time"); 
   }
   
   public static AttributeType createX509NameAttributeType(String attrID, String issuer, X500Principal value)
   {
      return getBareAttributeType(attrID, issuer, value, "urn:oasis:names:tc:xacml:1.0:data-type:x500Name"); 
   }
   
   private static AttributeType getBareAttributeType(String attrID, String issuer, Object value,
         String dataType)
   {
      AttributeType attributeType = new AttributeType();
      attributeType.setAttributeId(attrID);
      attributeType.setDataType(dataType);  
      if(issuer != null)
         attributeType.setIssuer(issuer);
      AttributeValueType avt = new AttributeValueType();
      avt.getContent().add(value);
      attributeType.getAttributeValue().add(avt);
      return attributeType; 
   }
   
   private static String getXMLDate()
   {
      DatatypeFactory dtf;
      try
      {
         dtf = DatatypeFactory.newInstance();
      }
      catch (DatatypeConfigurationException e)
      {
         throw new RuntimeException(e);
      } 
      XMLGregorianCalendar value = dtf.newXMLGregorianCalendar((GregorianCalendar) Calendar.getInstance());
      return value.toXMLFormat();
   }
}
