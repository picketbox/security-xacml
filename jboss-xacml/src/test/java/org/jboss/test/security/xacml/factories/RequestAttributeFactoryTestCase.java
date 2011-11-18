/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
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
package org.jboss.test.security.xacml.factories;

import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import junit.framework.Assert;

import org.jboss.security.xacml.core.model.context.AttributeType;
import org.jboss.security.xacml.factories.RequestAttributeFactory;
import org.junit.Test;


/**
 * Unit tests for the RequestAttributeFactory Attribute
 * @author dangradl@gmail.com
 * @since Nov 16, 2011
 */
public class RequestAttributeFactoryTestCase
{

	
	@Test
	public void shouldCreateDefaultTimeAttributeValue() throws Exception{
		AttributeType type=
				RequestAttributeFactory.createTimeAttributeType("x", null);
		String time=(String)type.getAttributeValue().get(0).getContent().get(0);
		XMLGregorianCalendar cal=DatatypeFactory.newInstance().newXMLGregorianCalendar(time);
		Assert.assertEquals("{http://www.w3.org/2001/XMLSchema}time", cal.getXMLSchemaType().toString());
	}
	@Test
	public void shouldCreateDefaultDateTimeAttributeValue() throws Exception{
		AttributeType type=
				RequestAttributeFactory.createDateTimeAttributeType("x", null);
		String datetime=(String)type.getAttributeValue().get(0).getContent().get(0);
		XMLGregorianCalendar cal=DatatypeFactory.newInstance().newXMLGregorianCalendar(datetime);
		Assert.assertEquals("{http://www.w3.org/2001/XMLSchema}dateTime", cal.getXMLSchemaType().toString());
	}
	@Test
	public void shouldCreateDefaultDateAttributeValue() throws Exception{
		AttributeType type=
				RequestAttributeFactory.createDateAttributeType("x", null);
		String datetime=(String)type.getAttributeValue().get(0).getContent().get(0);
		XMLGregorianCalendar cal=DatatypeFactory.newInstance().newXMLGregorianCalendar(datetime);
		Assert.assertEquals("{http://www.w3.org/2001/XMLSchema}date", cal.getXMLSchemaType().toString());
	}
}
