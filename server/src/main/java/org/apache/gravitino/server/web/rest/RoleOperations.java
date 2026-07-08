/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.gravitino.server.web.rest;

import com.codahale.metrics.annotation.ResponseMetered;
import com.codahale.metrics.annotation.Timed;
import com.google.common.collect.Sets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.gravitino.Entity;
import org.apache.gravitino.GravitinoEnv;
import org.apache.gravitino.MetadataObject;
import org.apache.gravitino.MetadataObjects;
import org.apache.gravitino.authorization.AccessControlDispatcher;
import org.apache.gravitino.authorization.AuthorizationUtils;
import org.apache.gravitino.authorization.BulkOperationResult;
import org.apache.gravitino.authorization.Privilege;
import org.apache.gravitino.authorization.RoleCreate;
import org.apache.gravitino.authorization.SecurableObject;
import org.apache.gravitino.authorization.SecurableObjects;
import org.apache.gravitino.dto.authorization.PrivilegeDTO;
import org.apache.gravitino.dto.authorization.SecurableObjectDTO;
import org.apache.gravitino.dto.requests.BulkRoleCreateRequest;
import org.apache.gravitino.dto.requests.RoleCreateRequest;
import org.apache.gravitino.dto.requests.RoleNamesRequest;
import org.apache.gravitino.dto.responses.BulkOperationFailureDTO;
import org.apache.gravitino.dto.responses.BulkOperationResponse;
import org.apache.gravitino.dto.responses.DropResponse;
import org.apache.gravitino.dto.responses.NameListResponse;
import org.apache.gravitino.dto.responses.RoleResponse;
import org.apache.gravitino.dto.util.DTOConverters;
import org.apache.gravitino.exceptions.IllegalMetadataObjectException;
import org.apache.gravitino.exceptions.NoSuchMetadataObjectException;
import org.apache.gravitino.metalake.MetalakeManager;
import org.apache.gravitino.metrics.MetricNames;
import org.apache.gravitino.server.authorization.MetadataAuthzHelper;
import org.apache.gravitino.server.authorization.NameBindings;
import org.apache.gravitino.server.authorization.annotations.AuthorizationExpression;
import org.apache.gravitino.server.authorization.annotations.AuthorizationMetadata;
import org.apache.gravitino.server.authorization.expression.AuthorizationExpressionConstants;
import org.apache.gravitino.server.web.Utils;
import org.apache.gravitino.utils.MetadataObjectUtil;
import org.apache.gravitino.utils.NameIdentifierUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@NameBindings.AccessControlInterfaces
@Path("/")
public class RoleOperations {
  private static final Logger LOG = LoggerFactory.getLogger(RoleOperations.class);

  private final AccessControlDispatcher accessControlManager;

  @Context private HttpServletRequest httpRequest;

  public RoleOperations() {
    this.accessControlManager = GravitinoEnv.getInstance().accessControlDispatcher();
  }

  @GET
  @Path("/metalakes/{metalake}/roles")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "list-role." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "list-role", absolute = true)
  @AuthorizationExpression(expression = "")
  public Response listRoles(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            MetalakeManager.checkMetalakeInUse(metalake);
            String[] names = accessControlManager.listRoleNames(metalake);
            names =
                MetadataAuthzHelper.filterByExpression(
                    metalake,
                    AuthorizationExpressionConstants.LOAD_ROLE_AUTHORIZATION_EXPRESSION,
                    Entity.EntityType.ROLE,
                    names,
                    roleName -> NameIdentifierUtil.ofRole(metalake, roleName));
            return Utils.ok(new NameListResponse(names));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(OperationType.LIST, "", metalake, e);
    }
  }

  @GET
  @Path("/metalakes/{metalake}/roles/{role}")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "get-role." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "get-role", absolute = true)
  @AuthorizationExpression(
      expression = AuthorizationExpressionConstants.LOAD_ROLE_AUTHORIZATION_EXPRESSION)
  public Response getRole(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      @PathParam("role") @AuthorizationMetadata(type = Entity.EntityType.ROLE) String role) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            MetalakeManager.checkMetalakeInUse(metalake);
            return Utils.ok(
                new RoleResponse(
                    DTOConverters.toDTO(accessControlManager.getRole(metalake, role))));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(OperationType.GET, role, metalake, e);
    }
  }

  @POST
  @Path("/metalakes/{metalake}/roles")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "create-role." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "create-role", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::CREATE_ROLE")
  public Response createRole(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      RoleCreateRequest request) {
    try {

      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            MetalakeManager.checkMetalakeInUse(metalake);
            return Utils.ok(
                new RoleResponse(
                    DTOConverters.toDTO(
                        accessControlManager.createRole(
                            metalake,
                            request.getName(),
                            request.getProperties(),
                            toSecurableObjects(metalake, request)))));
          });

    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(
          OperationType.CREATE, request.getName(), metalake, e);
    }
  }

  @DELETE
  @Path("/metalakes/{metalake}/roles/{role}")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "delete-role." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "delete-role", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || ROLE::OWNER")
  public Response deleteRole(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      @PathParam("role") @AuthorizationMetadata(type = Entity.EntityType.ROLE) String role) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            MetalakeManager.checkMetalakeInUse(metalake);
            boolean deleted = accessControlManager.deleteRole(metalake, role);
            if (!deleted) {
              LOG.warn("Failed to delete role {} under metalake {}", role, metalake);
            }
            return Utils.ok(new DropResponse(deleted, deleted));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(OperationType.DELETE, role, metalake, e);
    }
  }

  /**
   * Adds roles in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk role create request.
   * @return The bulk operation result.
   */
  @POST
  @Path("/bulk/metalakes/{metalake}/roles/add")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-add-roles." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-add-roles", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::CREATE_ROLE")
  public Response addRoles(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      BulkRoleCreateRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            MetalakeManager.checkMetalakeInUse(metalake);
            return Utils.ok(
                toBulkOperationResponse(
                    accessControlManager.bulkCreateRoles(
                        metalake, toRoleCreates(metalake, request.getRoles()))));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(OperationType.CREATE, "", metalake, e);
    }
  }

  /**
   * Removes roles in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk role names request.
   * @return The bulk operation result.
   */
  @POST
  @Path("/bulk/metalakes/{metalake}/roles/remove")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-remove-roles." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-remove-roles", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER")
  public Response removeRoles(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      RoleNamesRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            MetalakeManager.checkMetalakeInUse(metalake);
            return Utils.ok(
                toBulkOperationResponse(
                    accessControlManager.bulkDeleteRoles(metalake, request.getRoleNames())));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleRoleException(OperationType.DELETE, "", metalake, e);
    }
  }

  private static RoleCreate[] toRoleCreates(String metalake, RoleCreateRequest[] requests) {
    return Arrays.stream(requests)
        .map(
            request ->
                new RoleCreate(
                    request.getName(),
                    request.getProperties(),
                    toSecurableObjects(metalake, request)))
        .toArray(RoleCreate[]::new);
  }

  private static List<SecurableObject> toSecurableObjects(
      String metalake, RoleCreateRequest request) {
    Set<MetadataObject> metadataObjects = Sets.newHashSet();
    for (SecurableObjectDTO object : request.getSecurableObjects()) {
      MetadataObject metadataObject = MetadataObjects.parse(object.getFullName(), object.type());
      if (metadataObjects.contains(metadataObject)) {
        throw new IllegalArgumentException(
            String.format(
                "Doesn't support specifying duplicated securable objects %s type %s",
                object.fullName(), object.type()));
      }
      metadataObjects.add(metadataObject);

      Set<Privilege> privileges = Sets.newHashSet(object.privileges());
      AuthorizationUtils.checkDuplicatedNamePrivilege(privileges);
      try {
        for (Privilege privilege : object.privileges()) {
          AuthorizationUtils.checkPrivilege((PrivilegeDTO) privilege, object, metalake);
        }
        MetadataObjectUtil.checkMetadataObject(metalake, object);
      } catch (NoSuchMetadataObjectException nsm) {
        throw new IllegalMetadataObjectException(nsm);
      }
    }

    return Arrays.stream(request.getSecurableObjects())
        .map(
            securableObjectDTO ->
                SecurableObjects.parse(
                    securableObjectDTO.fullName(),
                    securableObjectDTO.type(),
                    securableObjectDTO.privileges().stream()
                        .map(privilege -> DTOConverters.fromPrivilegeDTO((PrivilegeDTO) privilege))
                        .collect(Collectors.toList())))
        .collect(Collectors.toList());
  }

  private static BulkOperationResponse toBulkOperationResponse(BulkOperationResult result) {
    return new BulkOperationResponse(
        result.succeeded(),
        Arrays.stream(result.failed())
            .map(failure -> new BulkOperationFailureDTO(failure.name(), failure.reason()))
            .toArray(BulkOperationFailureDTO[]::new));
  }
}
