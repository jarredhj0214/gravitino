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
import com.google.common.collect.Lists;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.Config;
import org.apache.gravitino.Entity;
import org.apache.gravitino.GravitinoEnv;
import org.apache.gravitino.MetadataObject;
import org.apache.gravitino.MetadataObjects;
import org.apache.gravitino.authorization.AccessControlDispatcher;
import org.apache.gravitino.authorization.Group;
import org.apache.gravitino.authorization.Owner;
import org.apache.gravitino.authorization.OwnerDispatcher;
import org.apache.gravitino.authorization.User;
import org.apache.gravitino.dto.authorization.GroupDTO;
import org.apache.gravitino.dto.authorization.UserDTO;
import org.apache.gravitino.dto.requests.BulkGroupAddRequest;
import org.apache.gravitino.dto.requests.BulkRemoveRequest;
import org.apache.gravitino.dto.requests.BulkUserAddRequest;
import org.apache.gravitino.dto.requests.GroupAddRequest;
import org.apache.gravitino.dto.requests.UserAddRequest;
import org.apache.gravitino.dto.responses.BulkError;
import org.apache.gravitino.dto.responses.BulkGroupResponse;
import org.apache.gravitino.dto.responses.BulkRemoveResponse;
import org.apache.gravitino.dto.responses.BulkSummary;
import org.apache.gravitino.dto.responses.BulkUserResponse;
import org.apache.gravitino.dto.responses.ErrorConstants;
import org.apache.gravitino.dto.util.DTOConverters;
import org.apache.gravitino.exceptions.AlreadyExistsException;
import org.apache.gravitino.exceptions.ForbiddenException;
import org.apache.gravitino.exceptions.NoSuchGroupException;
import org.apache.gravitino.exceptions.NoSuchUserException;
import org.apache.gravitino.exceptions.NotFoundException;
import org.apache.gravitino.exceptions.NotInUseException;
import org.apache.gravitino.metalake.MetalakeManager;
import org.apache.gravitino.metrics.MetricNames;
import org.apache.gravitino.server.ServerConfig;
import org.apache.gravitino.server.authorization.NameBindings;
import org.apache.gravitino.server.authorization.annotations.AuthorizationExpression;
import org.apache.gravitino.server.authorization.annotations.AuthorizationMetadata;
import org.apache.gravitino.server.web.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Provides best-effort bulk APIs for metalake access-control entities. */
@NameBindings.AccessControlInterfaces
@Path("/bulk/metalakes/{metalake}")
public class BulkOperations {

  private static final Logger LOG = LoggerFactory.getLogger(BulkOperations.class);

  private final AccessControlDispatcher accessControlManager;
  private final int bulkMaxItems;
  private final OwnerDispatcher ownerDispatcher;

  @Context private HttpServletRequest httpRequest;

  /** Creates a new bulk operations resource. */
  public BulkOperations() {
    this.accessControlManager = GravitinoEnv.getInstance().accessControlDispatcher();
    this.ownerDispatcher = GravitinoEnv.getInstance().ownerDispatcher();
    Config config = GravitinoEnv.getInstance().config();
    this.bulkMaxItems =
        config == null
            ? ServerConfig.BULK_MAX_ITEMS.getDefaultValue()
            : config.get(ServerConfig.BULK_MAX_ITEMS);
  }

  /**
   * Adds users in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk user add request.
   * @return The bulk user response.
   */
  @POST
  @Path("users/add")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-add-user." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-add-user", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::MANAGE_USERS")
  public Response addUsers(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      BulkUserAddRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            checkBulkSize("users", request.getUsers().length);
            MetalakeManager.checkMetalakeInUse(metalake);

            BulkResult<UserDTO> result =
                executeBulk(
                    Arrays.asList(request.getUsers()),
                    UserAddRequest::getName,
                    requestItem -> DTOConverters.toDTO(addUser(metalake, requestItem)));
            return Utils.ok(
                new BulkUserResponse(
                    result.successes.toArray(new UserDTO[0]),
                    result.errors.toArray(new BulkError[0]),
                    result.summary()));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleUserException(OperationType.ADD, "", metalake, e);
    }
  }

  /**
   * Removes users in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk remove request.
   * @return The bulk remove response.
   */
  @POST
  @Path("users/remove")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-remove-user." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-remove-user", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::MANAGE_USERS")
  public Response removeUsers(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      BulkRemoveRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            checkBulkSize("names", request.getNames().length);
            MetalakeManager.checkMetalakeInUse(metalake);

            Optional<Owner> metalakeOwner =
                ownerDispatcher.getOwner(
                    metalake, MetadataObjects.of(null, metalake, MetadataObject.Type.METALAKE));

            BulkResult<String> result =
                executeBulk(
                    Arrays.asList(request.getNames()),
                    Function.identity(),
                    name -> {
                      ensureUserIsNotMetalakeOwner(metalakeOwner, metalake, name);
                      if (!accessControlManager.removeUser(metalake, name)) {
                        throw new NoSuchUserException("User does not exist: %s", name);
                      }
                      return name;
                    });
            return Utils.ok(
                new BulkRemoveResponse(
                    result.successes.toArray(new String[0]),
                    result.errors.toArray(new BulkError[0]),
                    result.summary()));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleUserException(OperationType.REMOVE, "", metalake, e);
    }
  }

  /**
   * Adds groups in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk group add request.
   * @return The bulk group response.
   */
  @POST
  @Path("groups/add")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-add-group." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-add-group", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::MANAGE_GROUPS")
  public Response addGroups(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      BulkGroupAddRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            checkBulkSize("groups", request.getGroups().length);
            MetalakeManager.checkMetalakeInUse(metalake);

            BulkResult<GroupDTO> result =
                executeBulk(
                    Arrays.asList(request.getGroups()),
                    GroupAddRequest::getName,
                    requestItem -> DTOConverters.toDTO(addGroup(metalake, requestItem)));
            return Utils.ok(
                new BulkGroupResponse(
                    result.successes.toArray(new GroupDTO[0]),
                    result.errors.toArray(new BulkError[0]),
                    result.summary()));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleGroupException(OperationType.ADD, "", metalake, e);
    }
  }

  /**
   * Removes groups in bulk.
   *
   * @param metalake The metalake name.
   * @param request The bulk remove request.
   * @return The bulk remove response.
   */
  @POST
  @Path("groups/remove")
  @Produces("application/vnd.gravitino.v1+json")
  @Timed(name = "bulk-remove-group." + MetricNames.HTTP_PROCESS_DURATION, absolute = true)
  @ResponseMetered(name = "bulk-remove-group", absolute = true)
  @AuthorizationExpression(expression = "METALAKE::OWNER || METALAKE::MANAGE_GROUPS")
  public Response removeGroups(
      @PathParam("metalake") @AuthorizationMetadata(type = Entity.EntityType.METALAKE)
          String metalake,
      BulkRemoveRequest request) {
    try {
      return Utils.doAs(
          httpRequest,
          () -> {
            request.validate();
            checkBulkSize("names", request.getNames().length);
            MetalakeManager.checkMetalakeInUse(metalake);

            Optional<Owner> metalakeOwner =
                ownerDispatcher.getOwner(
                    metalake, MetadataObjects.of(null, metalake, MetadataObject.Type.METALAKE));

            BulkResult<String> result =
                executeBulk(
                    Arrays.asList(request.getNames()),
                    Function.identity(),
                    name -> {
                      ensureGroupIsNotMetalakeOwner(metalakeOwner, metalake, name);
                      if (!accessControlManager.removeGroup(metalake, name)) {
                        throw new NoSuchGroupException("Group does not exist: %s", name);
                      }
                      return name;
                    });
            return Utils.ok(
                new BulkRemoveResponse(
                    result.successes.toArray(new String[0]),
                    result.errors.toArray(new BulkError[0]),
                    result.summary()));
          });
    } catch (Exception e) {
      return ExceptionHandlers.handleGroupException(OperationType.REMOVE, "", metalake, e);
    }
  }

  private User addUser(String metalake, UserAddRequest request) {
    return StringUtils.isNotBlank(request.getExternalId())
        ? accessControlManager.addUser(
            metalake,
            request.getName(),
            request.getExternalId(),
            Optional.ofNullable(request.getEnabled()).orElse(true))
        : accessControlManager.addUser(metalake, request.getName());
  }

  private Group addGroup(String metalake, GroupAddRequest request) {
    return StringUtils.isNotBlank(request.getExternalId())
        ? accessControlManager.addGroup(metalake, request.getName(), request.getExternalId())
        : accessControlManager.addGroup(metalake, request.getName());
  }

  private void checkBulkSize(String fieldName, int size) {
    if (size > bulkMaxItems) {
      throw new IllegalArgumentException(
          String.format(
              "\"%s\" size %d exceeds the maximum allowed bulk items %d",
              fieldName, size, bulkMaxItems));
    }
  }

  private void ensureUserIsNotMetalakeOwner(
      Optional<Owner> metalakeOwner, String metalake, String user) {
    metalakeOwner.ifPresent(
        owner -> {
          if (owner.type() == Owner.Type.USER && owner.name().equals(user)) {
            throw new IllegalArgumentException(
                String.format(
                    "Cannot remove user %s from metalake %s because the user is the owner of the metalake.",
                    user, metalake));
          }
        });
  }

  private void ensureGroupIsNotMetalakeOwner(
      Optional<Owner> metalakeOwner, String metalake, String group) {
    metalakeOwner.ifPresent(
        owner -> {
          if (owner.type() == Owner.Type.GROUP && owner.name().equals(group)) {
            throw new IllegalArgumentException(
                String.format(
                    "Cannot remove group %s from metalake %s because the group is the owner of the metalake.",
                    group, metalake));
          }
        });
  }

  private <I, O> BulkResult<O> executeBulk(
      List<I> items, Function<I, String> nameExtractor, BulkItemExecutor<I, O> executor) {
    List<O> successes = Lists.newArrayList();
    List<BulkError> errors = Lists.newArrayList();

    for (int index = 0; index < items.size(); index++) {
      I item = items.get(index);
      String name = nameExtractor.apply(item);
      try {
        successes.add(executor.execute(item));
      } catch (Exception e) {
        LOG.warn("Failed to execute bulk item {} name {}", index, name, e);
        errors.add(toBulkError(index, name, e));
      }
    }

    return new BulkResult<>(successes, errors, items.size());
  }

  private BulkError toBulkError(int index, String name, Exception e) {
    return new BulkError(index, name, errorCode(e), e.getClass().getSimpleName(), e.getMessage());
  }

  private int errorCode(Exception e) {
    if (e instanceof IllegalArgumentException) {
      return ErrorConstants.ILLEGAL_ARGUMENTS_CODE;
    } else if (e instanceof NotFoundException) {
      return ErrorConstants.NOT_FOUND_CODE;
    } else if (e instanceof AlreadyExistsException) {
      return ErrorConstants.ALREADY_EXISTS_CODE;
    } else if (e instanceof ForbiddenException) {
      return ErrorConstants.FORBIDDEN_CODE;
    } else if (e instanceof NotInUseException) {
      return ErrorConstants.NOT_IN_USE_CODE;
    }
    return ErrorConstants.INTERNAL_ERROR_CODE;
  }

  private interface BulkItemExecutor<I, O> {
    O execute(I item) throws Exception;
  }

  private static class BulkResult<T> {
    private final List<T> successes;
    private final List<BulkError> errors;
    private final int total;

    private BulkResult(List<T> successes, List<BulkError> errors, int total) {
      this.successes = successes;
      this.errors = errors;
      this.total = total;
    }

    private BulkSummary summary() {
      return new BulkSummary(total, successes.size(), errors.size());
    }
  }
}
