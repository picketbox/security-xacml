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
package org.jboss.security.xacml.saml.integration.opensaml.util;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

/**
 *  Utility class to create OpenSAML2 objects
 *  @author Anil.Saldhana@redhat.com
 *  @since  Mar 27, 2008 
 *  @version $Revision$
 */
public class SAML2Util
{ 
   public SAML2Util()
   {
      super(); 
   }

   public XMLObjectBuilder<?> getBuilder(QName qname)
   {
     return Configuration.getBuilderFactory().getBuilder(qname);   
   }
   
   public XMLObject buildXMLObject(QName qname)
   {
      XMLObjectBuilder<?> ob = getBuilder(qname);
      return ob.buildObject(qname.getNamespaceURI(), qname.getLocalPart(), qname.getPrefix());
   } 
   
   public XSString buildXSString(QName qname)
   {
      XMLObjectBuilder<?> stringBuilder = getBuilder(XSString.TYPE_NAME);
      return (XSString) stringBuilder.buildObject(qname, XSString.TYPE_NAME);
   }
   
   public DateTime getIssueInstant()
   {
      return new DateTime(ISOChronology.getInstanceUTC());
   }
   
   public Element toElement(XMLObject xmlObj) throws MarshallingException
   {
      Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(xmlObj); 
      return marshaller.marshall(xmlObj);
   }
   
   public String toString(XMLObject xmlObj) throws MarshallingException
   {
      return XMLHelper.prettyPrintXML(toElement(xmlObj));
   }
   
   public XMLObject toXMLObject(Element element) throws UnmarshallingException
   {
      if(element ==null)
         throw new IllegalArgumentException("Null Element");
      UnmarshallerFactory factory = Configuration.getUnmarshallerFactory();
      Unmarshaller unmarshaller = factory.getUnmarshaller(element); 
      if(unmarshaller == null)
         throw new IllegalStateException("Unmarshaller for element "+element.getLocalName() 
               + " is null");
      return unmarshaller.unmarshall(element);
   }
}