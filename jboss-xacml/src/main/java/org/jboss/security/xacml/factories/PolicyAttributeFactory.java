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
import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;

import org.jboss.security.xacml.core.model.policy.AttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.AttributeValueType;
import org.jboss.security.xacml.core.model.policy.SubjectAttributeDesignatorType;
import org.jboss.security.xacml.interfaces.XMLSchemaConstants;

//$Id$

/**
 *  Static class that has methods to create AttributeValueTypes
 *  for constructing policies
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class PolicyAttributeFactory
{

   public static AttributeValueType createAnyURIAttributeType(URI value)
   {
      return getBareAttributeValueType("" + value, XMLSchemaConstants.DATATYPE_ANYURI);
   }

   public static AttributeValueType createBase64BinaryAttributeType(byte[] value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_BASE64BINARY);
   }

   public static AttributeValueType createBooleanAttributeType(boolean value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_BOOLEAN);
   }

   public static AttributeValueType createDateAttributeType()
   {
      return getBareAttributeValueType(getXMLDate(), XMLSchemaConstants.DATATYPE_DATE);
   }

   public static AttributeValueType createDateAttributeType(XMLGregorianCalendar value)
   {
      return getBareAttributeValueType(value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE);
   }

   public static AttributeValueType createDateTimeAttributeType()
   {
      return getBareAttributeValueType(getXMLDate(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }

   public static AttributeValueType createDateTimeAttributeType(XMLGregorianCalendar value)
   {
      return getBareAttributeValueType(value.toXMLFormat(), XMLSchemaConstants.DATATYPE_DATE_TIME);
   }

   public static AttributeValueType createDNSNameAttributeType(String hostname)
   {
      return getBareAttributeValueType(hostname, XMLSchemaConstants.DATATYPE_DNSNAME);
   }

   public static AttributeValueType createDoubleAttributeType(double value)
   {
      return getBareAttributeValueType("" + value, XMLSchemaConstants.DATATYPE_DOUBLE);
   }

   public static AttributeValueType createEmailAttributeType(String value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_RFC822NAME);
   }

   public static AttributeValueType createHexBinaryAttributeType(byte[] value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_HEXBINARY);
   }

   public static AttributeValueType createIntegerAttributeType(int value)
   {
      return getBareAttributeValueType("" + value, XMLSchemaConstants.DATATYPE_INTEGER);
   }

   public static AttributeValueType createIPAddressAttributeType(InetAddress address)
   {
      return getBareAttributeValueType(address, XMLSchemaConstants.DATATYPE_IPADDRESS);
   }

   public static AttributeValueType createStringAttributeType(String value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_STRING);
   }

   public static AttributeValueType createTimeAttributeType()
   {
      return getBareAttributeValueType(getXMLDate(), XMLSchemaConstants.DATATYPE_TIME);
   }

   public static AttributeValueType createTimeAttributeType(XMLGregorianCalendar value)
   {
      return getBareAttributeValueType(value.toXMLFormat(), XMLSchemaConstants.DATATYPE_TIME);
   }

   public static AttributeValueType createX509NameAttributeType(X500Principal value)
   {
      return getBareAttributeValueType(value, XMLSchemaConstants.DATATYPE_X500NAME);
   }

   public static AttributeValueType createDayTimeDurationAttributeType(Duration value)
   {
      return getBareAttributeValueType(value.toString(), XMLSchemaConstants.DATATYPE_DAYTIMEDURATION);
   }

   public static AttributeValueType createYearMonthDurationAttributeType(Duration value)
   {
      return getBareAttributeValueType(value.toString(), XMLSchemaConstants.DATATYPE_YEARMONTHDURATION);
   }

   public static AttributeDesignatorType createAttributeDesignatorType(String id, String dataType, String issuer,
         boolean mustBePresent)
   {
      AttributeDesignatorType adt = new AttributeDesignatorType();
      adt.setAttributeId(id);
      adt.setDataType(dataType);
      if (issuer != null)
         adt.setIssuer(issuer);
      adt.setMustBePresent(mustBePresent);
      return adt;
   }

   public static SubjectAttributeDesignatorType createSubjectAttributeDesignatorType(String id, String dataType,
         String issuer, boolean mustBePresent, String subjectCategory)
   {
      SubjectAttributeDesignatorType adt = new SubjectAttributeDesignatorType();
      adt.setAttributeId(id);
      adt.setDataType(dataType);
      if (issuer != null)
         adt.setIssuer(issuer);
      adt.setMustBePresent(mustBePresent);
      if (subjectCategory != null)
         adt.setSubjectCategory(subjectCategory);
      return adt;
   }

   private static AttributeValueType getBareAttributeValueType(Object value, String dataType)
   {
      AttributeValueType avt = new AttributeValueType();
      avt.setDataType(dataType);
      avt.getContent().add(value);
      return avt;
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
