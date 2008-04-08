/*
  * JBoss, Home of Professional Open Source
  * Copyright 2005, JBoss Inc., and individual contributors as indicated
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
package org.jboss.test.security.test.xacml.modules;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

import org.jboss.security.xacml.sunxacml.AbstractPolicy;
import org.jboss.security.xacml.sunxacml.EvaluationCtx;
import org.jboss.security.xacml.sunxacml.ParsingException;
import org.jboss.security.xacml.sunxacml.UnknownIdentifierException;
import org.jboss.security.xacml.sunxacml.combine.CombiningAlgFactory;
import org.jboss.security.xacml.sunxacml.combine.PolicyCombiningAlgorithm;
import org.jboss.security.xacml.sunxacml.ctx.Status;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinder;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderModule;
import org.jboss.security.xacml.sunxacml.finder.PolicyFinderResult;
import org.jboss.security.xacml.sunxacml.support.finder.PolicyCollection;
import org.jboss.security.xacml.sunxacml.support.finder.PolicyReader;
import org.jboss.security.xacml.sunxacml.support.finder.StaticPolicyFinderModule;
import org.jboss.security.xacml.sunxacml.support.finder.TopLevelPolicyException;

//$Id: JBossStaticPolicyFinderModule.java 45389 2006-05-30 21:29:37Z asaldhana $

/**
 *  Policy Finder Module that is based on the StaticPolicyFinderModule
 *  but will always provide a status of syntax error if there has been
 *  a parsing exception in policy file(s)
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  May 30, 2006 
 *  @version $Revision: 45389 $
 */
public class JBossStaticPolicyFinderModule extends PolicyFinderModule
{
   // the list of policy URLs passed to the constructor
   private List policyList;

   // the map of policies
   private PolicyCollection policies;

   // the optional schema file
   private File schemaFile = null;

   // the policy identifier for any policy sets we dynamically create
   private static final String POLICY_ID = "urn:com:sun:xacml:support:finder:dynamic-policy-set";

   private static URI policyId = null;

   // the logger we'll use for all messages
   private static final Logger log = Logger.getLogger(StaticPolicyFinderModule.class.getName());

   //Was there an encounter of parse exception?
   private boolean encounteredParsingException = false;

   static
   {
      try
      {
         policyId = new URI(POLICY_ID);
      }
      catch (Exception e)
      {
         log.severe("couldn't assign default policy id: " + e.getMessage());
      }
   };

   /**
    * Creates a <code>StaticPolicyFinderModule</code> that provides
    * access to the given collection of policies and returns an error when
    * more than one policy matches a given context. Any policy that cannot
    * be loaded will be noted in the log, but will not cause an error. The
    * schema file used to validate policies is defined by the property
    * <code>PolicyReader.POLICY_SCHEMA_PROPERTY</code>. If the retrieved
    * property is null, then no schema validation will occur.
    *
    * @param policyList a <code>List</code> of <code>String</code>s that
    *                   represent URLs or files pointing to XACML policies
    */
   public JBossStaticPolicyFinderModule(List policyList)
   {
      this.policyList = policyList;
      this.policies = new PolicyCollection();

      String schemaName = System.getProperty(PolicyReader.POLICY_SCHEMA_PROPERTY);
      if (schemaName != null)
         schemaFile = new File(schemaName);
   }

   /**
    * Creates a <code>StaticPolicyFinderModule</code> that provides
    * access to the given collection of policies and returns an error when
    * more than one policy matches a given context. Any policy that cannot
    * be loaded will be noted in the log, but will not cause an error.
    *
    * @param policyList a <code>List</code> of <code>String</code>s that
    *                   represent URLs or files pointing to XACML policies
    * @param schemaFile the schema file to validate policies against,
    *                   or null if schema validation is not desired
    */
   public JBossStaticPolicyFinderModule(List policyList, String schemaFile)
   {
      this.policyList = policyList;
      this.policies = new PolicyCollection();

      if (schemaFile != null)
         this.schemaFile = new File(schemaFile);
   }

   /**
    * Creates a <code>StaticPolicyFinderModule</code> that provides
    * access to the given collection of policies. The given combining
    * algorithm is used to create new PolicySets when more than one
    * policy applies. Any policy that cannot be loaded will be noted in
    * the log, but will not cause an error. The schema file used to
    * validate policies is defined by the property
    * <code>PolicyReader.POLICY_SCHEMA_PROPERTY</code>. If the retrieved
    * property is null, then no schema validation will occur.
    *
    * @param combiningAlg the algorithm to use in a new PolicySet when more
    *                     than one policy applies
    * @param policyList a <code>List</code> of <code>String</code>s that
    *                   represent URLs or files pointing to XACML policies
    *
    * @throws URISyntaxException if the combining algorithm is not a
    *                            well-formed URI
    * @throws UnknownIdentifierException if the combining algorithm identifier
    *                                    isn't known
    */
   public JBossStaticPolicyFinderModule(String combiningAlg, List policyList) throws URISyntaxException,
         UnknownIdentifierException
   {
      PolicyCombiningAlgorithm alg = (PolicyCombiningAlgorithm) (CombiningAlgFactory.getInstance()
            .createAlgorithm(new URI(combiningAlg)));

      this.policyList = policyList;
      this.policies = new PolicyCollection(alg, policyId);

      String schemaName = System.getProperty(PolicyReader.POLICY_SCHEMA_PROPERTY);
      if (schemaName != null)
         schemaFile = new File(schemaName);
   }

   /**
    * Creates a <code>StaticPolicyFinderModule</code> that provides
    * access to the given collection of policies. The given combining
    * algorithm is used to create new PolicySets when more than one
    * policy applies. Any policy that cannot be loaded will be noted in
    * the log, but will not cause an error.
    *
    * @param combiningAlg the algorithm to use in a new PolicySet when more
    *                     than one policy applies
    * @param policyList a <code>List</code> of <code>String</code>s that
    *                   represent URLs or files pointing to XACML policies
    * @param schemaFile the schema file to validate policies against,
    *                   or null if schema validation is not desired
    *
    * @throws URISyntaxException if the combining algorithm is not a
    *                            well-formed URI
    * @throws UnknownIdentifierException if the combining algorithm identifier
    *                                    isn't known
    */
   public JBossStaticPolicyFinderModule(String combiningAlg, List policyList, String schemaFile)
         throws URISyntaxException, UnknownIdentifierException
   {
      PolicyCombiningAlgorithm alg = (PolicyCombiningAlgorithm) (CombiningAlgFactory.getInstance()
            .createAlgorithm(new URI(combiningAlg)));

      this.policyList = policyList;
      this.policies = new PolicyCollection(alg, policyId);

      if (schemaFile != null)
         this.schemaFile = new File(schemaFile);
   }

   /**
    * Always returns <code>true</code> since this module does support
    * finding policies based on context.
    *
    * @return true
    */
   public boolean isRequestSupported()
   {
      return true;
   }

   /**
    * Initialize this module. Typically this is called by
    * <code>PolicyFinder</code> when a PDP is created. This method is
    * where the policies are actually loaded.
    *
    * @param finder the <code>PolicyFinder</code> using this module
    */
   public void init(PolicyFinder finder)
   {
      String clazzName = JBossStaticPolicyFinderModule.class.getName();
      // now that we have the PolicyFinder, we can load the policies
      PolicyReader reader = new PolicyReader(finder, java.util.logging.Logger.getLogger(clazzName), schemaFile);

      Iterator it = policyList.iterator();
      while (it.hasNext())
      {
         String str = (String) (it.next());
         AbstractPolicy policy = null;
         try
         {
            try
            {
               // first try to load it as a URL
               URL url = new URL(str);
               policy = reader.readPolicy(url);
            }
            catch (MalformedURLException murle)
            {
               // assume that this is a filename, and try again
               policy = reader.readPolicy(new File(str));
            }
         }
         catch (ParsingException e)
         {
            this.encounteredParsingException = true;
            log.severe("Parsing Exception in policy: " + e.getMessage());
            continue;
         }

         // we loaded the policy, so try putting it in the collection
         if (!policies.addPolicy(policy))
            log.warning("tried to load the same " + "policy multiple times: " + str);
      }
   }

   /**
    * Finds a policy based on a request's context. If more than one policy
    * matches, then this either returns an error or a new policy wrapping
    * the multiple policies (depending on which constructor was used to
    * construct this instance).
    *
    * @param context the representation of the request data
    *
    * @return the result of trying to find an applicable policy
    */
   public PolicyFinderResult findPolicy(EvaluationCtx context)
   {
      List aList = new ArrayList();
      aList.add(Status.STATUS_SYNTAX_ERROR);

      try
      {
         if (this.encounteredParsingException)
            return new PolicyFinderResult(new Status(aList));
         AbstractPolicy policy = policies.getPolicy(context);

         if (policy == null)
            return new PolicyFinderResult();
         else
            return new PolicyFinderResult(policy);
      }
      catch (TopLevelPolicyException tlpe)
      {
         return new PolicyFinderResult(tlpe.getStatus());
      }
   }
}
