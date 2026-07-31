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

import com.google.common.collect.Sets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.gravitino.MetadataObject;
import org.apache.gravitino.MetadataObjects;
import org.apache.gravitino.authorization.AuthorizationUtils;
import org.apache.gravitino.authorization.Privilege;
import org.apache.gravitino.authorization.SecurableObject;
import org.apache.gravitino.authorization.SecurableObjects;
import org.apache.gravitino.dto.authorization.PrivilegeDTO;
import org.apache.gravitino.dto.authorization.SecurableObjectDTO;
import org.apache.gravitino.dto.requests.RoleCreateRequest;
import org.apache.gravitino.dto.util.DTOConverters;
import org.apache.gravitino.exceptions.IllegalMetadataObjectException;
import org.apache.gravitino.exceptions.NoSuchMetadataObjectException;
import org.apache.gravitino.utils.MetadataObjectUtil;

/** Shared utilities for validating and converting role creation requests. */
class RoleRequestUtils {

  private RoleRequestUtils() {}

  /**
   * Validates the securable objects in a role creation request and converts them to domain objects.
   *
   * @param metalake The metalake name.
   * @param request The role creation request.
   * @return The list of validated securable objects.
   */
  static List<SecurableObject> validateAndConvertSecurableObjects(
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
}
