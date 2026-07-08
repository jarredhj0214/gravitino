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
package org.apache.gravitino.authorization;

import java.util.List;
import java.util.Map;

/** Represents a Role to create. */
public class RoleCreate {

  private final String name;
  private final Map<String, String> properties;
  private final List<SecurableObject> securableObjects;

  /**
   * Creates a new RoleCreate instance.
   *
   * @param name The name of the Role.
   * @param properties The properties of the Role.
   * @param securableObjects The securable objects of the Role.
   */
  public RoleCreate(
      String name, Map<String, String> properties, List<SecurableObject> securableObjects) {
    this.name = name;
    this.properties = properties;
    this.securableObjects = securableObjects;
  }

  /**
   * Gets the name of the Role.
   *
   * @return The name of the Role.
   */
  public String name() {
    return name;
  }

  /**
   * Gets the properties of the Role.
   *
   * @return The properties of the Role.
   */
  public Map<String, String> properties() {
    return properties;
  }

  /**
   * Gets the securable objects of the Role.
   *
   * @return The securable objects of the Role.
   */
  public List<SecurableObject> securableObjects() {
    return securableObjects;
  }
}
