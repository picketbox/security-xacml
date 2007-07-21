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
package org.jboss.test.security.xacml.bindings.web;

import java.net.URI;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.JAXBElement;

import junit.framework.TestCase;

import org.jboss.security.xacml.core.JBossPDP;
import org.jboss.security.xacml.core.model.policy.ActionMatchType;
import org.jboss.security.xacml.core.model.policy.ActionType;
import org.jboss.security.xacml.core.model.policy.ActionsType;
import org.jboss.security.xacml.core.model.policy.ApplyType;
import org.jboss.security.xacml.core.model.policy.AttributeValueType;
import org.jboss.security.xacml.core.model.policy.ConditionType;
import org.jboss.security.xacml.core.model.policy.EffectType;
import org.jboss.security.xacml.core.model.policy.ExpressionType;
import org.jboss.security.xacml.core.model.policy.FunctionType;
import org.jboss.security.xacml.core.model.policy.ObjectFactory;
import org.jboss.security.xacml.core.model.policy.PolicyType;
import org.jboss.security.xacml.core.model.policy.ResourceMatchType;
import org.jboss.security.xacml.core.model.policy.ResourceType;
import org.jboss.security.xacml.core.model.policy.ResourcesType;
import org.jboss.security.xacml.core.model.policy.RuleType;
import org.jboss.security.xacml.core.model.policy.SubjectAttributeDesignatorType;
import org.jboss.security.xacml.core.model.policy.TargetType;
import org.jboss.security.xacml.factories.PolicyAttributeFactory;
import org.jboss.security.xacml.factories.PolicyFactory;
import org.jboss.security.xacml.interfaces.PolicyDecisionPoint;
import org.jboss.security.xacml.interfaces.PolicyLocator;
import org.jboss.security.xacml.interfaces.RequestContext;
import org.jboss.security.xacml.interfaces.ResponseContext;
import org.jboss.security.xacml.interfaces.XACMLConstants;
import org.jboss.security.xacml.interfaces.XACMLPolicy;
import org.jboss.security.xacml.interfaces.XMLSchemaConstants;
import org.jboss.security.xacml.locators.JBossPolicyLocator;

//$Id$

/**
 *  Test Case that constructs the policy dynamically
 *  and then applies the web access rules
 *  @author Anil.Saldhana@redhat.com
 *  @since  Jul 20, 2007 
 *  @version $Revision$
 */
public class WebLayerDynamicPolicyUnitTestCase extends TestCase
{
   private boolean debug = false; //Enable for request trace  
    
   public void testWebBinding() throws Exception
   {  
      PolicyType policyType = constructPolicy();
      PolicyDecisionPoint pdp = new JBossPDP();
      
      XACMLPolicy policy = PolicyFactory.createPolicy(policyType);
      Set<XACMLPolicy> policies = new HashSet<XACMLPolicy>();
      policies.add(policy);
      
      pdp.setPolicies(policies);
      
      //Add the basic locators also
      PolicyLocator policyLocator = new JBossPolicyLocator();
      policyLocator.setPolicies(policies); //Locators need to be given the policies
      
      Set<PolicyLocator> locators = new HashSet<PolicyLocator>();
      locators.add(policyLocator);
      pdp.setLocators(locators);
      assertNotNull("JBossPDP is != null", pdp);
      
      Principal p = new Principal()
      { 
         public String getName()
         { 
            return "testuser";
         } 
      };

      //Create Role Group
      Group grp = this.getRoleGroup("developer");
      
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check PERMIT condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      if(debug)
        request.marshall(System.out);
      
      assertEquals("Access Allowed?", XACMLConstants.DECISION_PERMIT,
            getDecision(pdp,request)); 
   }
   
   public void testNegativeAccessWebBinding() throws Exception
   {
      PolicyType policyType = constructPolicy();
      PolicyDecisionPoint pdp = new JBossPDP();
      
      XACMLPolicy policy = PolicyFactory.createPolicy(policyType);
      Set<XACMLPolicy> policies = new HashSet<XACMLPolicy>();
      policies.add(policy);
      
      pdp.setPolicies(policies);
      
      //Add the basic locators also
      PolicyLocator policyLocator = new JBossPolicyLocator();
      policyLocator.setPolicies(policies); //Locators need to be given the policies
      
      Set<PolicyLocator> locators = new HashSet<PolicyLocator>();
      locators.add(policyLocator);
      pdp.setLocators(locators);
      assertNotNull("JBossPDP is != null", pdp);
      
      
      Principal p = new Principal()
      { 
         public String getName()
         { 
            return "testuser";
         } 
      };

      //Create Role Group
      Group grp = this.getRoleGroup("imposter");
      String requestURI = "http://test/developer-guide.html";
      HttpRequestUtil util = new HttpRequestUtil();
      HttpServletRequest req = util.createRequest(p, requestURI); 
      
      //Check DENY condition
      WebPEP pep = new WebPEP();
      RequestContext request = pep.createXACMLRequest(req, p, grp);
      request.marshall(System.out);
      
      assertEquals("Access Disallowed?", XACMLConstants.DECISION_DENY,
            getDecision(pdp,request));  
   }  
   
   
   
   private PolicyType constructPolicy() throws Exception
   {
      ObjectFactory objectFactory = new ObjectFactory();
      
      String PERMIT_OVERRIDES="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:permit-overrides";
      PolicyType policyType = new PolicyType();
      policyType.setPolicyId("ExamplePolicy");
      policyType.setVersion("2.0");
      policyType.setRuleCombiningAlgId(PERMIT_OVERRIDES);
      
      //Create a target
      TargetType targetType = new TargetType(); 
      
      ResourcesType resourcesType = new ResourcesType();
      ResourceType resourceType = new ResourceType();
      ResourceMatchType rmt = new ResourceMatchType();
      rmt.setMatchId(XACMLConstants.FUNCTION_ANYURI_EQUALS);
      rmt.setResourceAttributeDesignator(PolicyAttributeFactory.createAttributeDesignatorType(
                   XACMLConstants.RESOURCE_IDENTIFIER,XMLSchemaConstants.DATATYPE_ANYURI));
      rmt.setAttributeValue(PolicyAttributeFactory.createAnyURIAttributeType(
                                             new URI("http://test/developer-guide.html")));
      resourceType.getResourceMatch().add(rmt);
      resourcesType.getResource().add(resourceType);
      
      targetType.setResources(resourcesType);
      
      policyType.setTarget(targetType);
      
      
      //Create a Rule
      RuleType permitRule = new RuleType();
      permitRule.setRuleId("ReadRule");
      permitRule.setEffect(EffectType.PERMIT);
      
      ActionsType permitRuleActionsType = new ActionsType();
      ActionType permitRuleActionType = new ActionType();
      
      ActionMatchType amct = new ActionMatchType();
      amct.setMatchId("urn:oasis:names:tc:xacml:1.0:function:string-equal");
      amct.setAttributeValue(PolicyAttributeFactory.createStringAttributeType("read"));
      amct.setActionAttributeDesignator(PolicyAttributeFactory.createAttributeDesignatorType(
            XACMLConstants.ACTION_IDENTIFIER, XMLSchemaConstants.DATATYPE_STRING)); 
      permitRuleActionType.getActionMatch().add(amct);
      TargetType permitRuleTargetType = new TargetType();
      permitRuleActionsType.getAction().add(permitRuleActionType);
      permitRuleTargetType.setActions(permitRuleActionsType);
      permitRule.setTarget(permitRuleTargetType);
      
      ConditionType permitRuleConditionType = new ConditionType();  
      FunctionType functionType = new FunctionType();
      functionType.setFunctionId(XACMLConstants.FUNCTION_STRING_EQUAL);
      JAXBElement<ExpressionType> jaxbElementFunctionType = objectFactory.createExpression(functionType);
      permitRuleConditionType.setExpression(jaxbElementFunctionType);
      
      ApplyType permitRuleApplyType = new ApplyType();
      permitRuleApplyType.setFunctionId(XACMLConstants.FUNCTION_STRING_IS_IN);
       
      SubjectAttributeDesignatorType sadt = PolicyAttributeFactory.createSubjectAttributeDesignatorType(
            XACMLConstants.SUBJECT_ROLE_IDENTIFIER, XMLSchemaConstants.DATATYPE_STRING);
      JAXBElement<SubjectAttributeDesignatorType> sadtElement = objectFactory.createSubjectAttributeDesignator(sadt);
      AttributeValueType avt = PolicyAttributeFactory.createStringAttributeType("developer");
      JAXBElement<AttributeValueType> jaxbAVT = objectFactory.createAttributeValue(avt); 
      permitRuleApplyType.getExpression().add(jaxbAVT); 
      permitRuleApplyType.getExpression().add(sadtElement);
       
      
      permitRuleConditionType.setExpression(objectFactory.createApply(permitRuleApplyType));
       
      permitRule.setCondition(permitRuleConditionType);
      
      policyType.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().add(permitRule);
      //Create a Deny Rule
      RuleType denyRule = new RuleType();
      denyRule.setRuleId("DenyRule"); 
      denyRule.setEffect(EffectType.DENY); 
      policyType.getCombinerParametersOrRuleCombinerParametersOrVariableDefinition().add(denyRule);
      
      return policyType;
   }
   
   private int getDecision(PolicyDecisionPoint pdp, RequestContext request) throws Exception
   { 
      ResponseContext response = pdp.evaluate(request);
      assertNotNull("Response is not null", response);
      return response.getDecision(); 
   }
   
   private Group getRoleGroup( final String roleName)
   {
      return new Group() {

         private Vector vect = new Vector();
         public boolean addMember(final Principal principal)
         { 
            return vect.add(principal);
         }

         public boolean isMember(Principal principal)
         { 
            return vect.contains(principal);
         }

         public Enumeration<? extends Principal> members()
         { 
            vect.add(new Principal()
            {

               public String getName()
               { 
                  return roleName;
               }});
            return vect.elements();
         }

         public boolean removeMember(Principal principal)
         { 
            return vect.remove(principal);
         }

         public String getName()
         { 
            return "ROLES";
         }
       }; 
   } 
}
