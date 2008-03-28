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
package org.jboss.security.xacml.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.jboss.security.xacml.sunxacml.Policy;
import org.jboss.security.xacml.sunxacml.PolicySet;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;


/**
 * Create an XACML Policy Object from the url for the policy xml
 * @author Anil.Saldhana@redhat.com
 *  @since  Jul 6, 2007 
 *  @version $Revision$
 */
public class XACMLPolicyUtil 
{
   /**
    * Create a PolicySet
    * @param location location of the policy set file
    * @param finder PolicyFinder instance
    * @return
    * @throws Exception
    */
	public PolicySet createPolicySet(URL location, PolicyFinder finder) throws Exception
	{
        return createPolicySet(location.openStream(),  finder); 
	}
	
    /**
     * Create a policyset
     * @param is
     * @param finder
     * @return
     * @throws Exception
     */
	public PolicySet createPolicySet(InputStream is, PolicyFinder finder) throws Exception  
	{
       if(finder == null)
          throw new IllegalArgumentException("Policy Finder is null");
		Document doc = getDocument(is);
		return PolicySet.getInstance(doc.getFirstChild(), finder); 
	}

    /**
     * Create a Policy
     * @param location Policy File
     * @return
     * @throws Exception
     */
	public Policy createPolicy(URL location) throws Exception
	{  
		return createPolicy(location.openStream());
	}

    /**
     * Create a policy
     * @param is Inputstream of the policy file
     * @return
     * @throws Exception
     */
	public Policy createPolicy(InputStream is) throws Exception
	{ 
		Document doc = getDocument(is);
		return Policy.getInstance(doc.getFirstChild());
	}

	private Document getDocument(InputStream is)
	throws ParserConfigurationException, SAXException, IOException 
	{
		DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
		docBuilderFactory.setNamespaceAware(true); 
		DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
		Document doc = docBuilder.parse (is);
		return doc;
	}
}
