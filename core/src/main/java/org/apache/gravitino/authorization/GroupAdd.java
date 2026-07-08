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

import javax.annotation.Nullable;

/** Represents a Group to add. */
public class GroupAdd {

  private final String name;
  @Nullable private final String externalId;

  /**
   * Creates a new GroupAdd instance.
   *
   * @param name The name of the Group.
   * @param externalId The external identifier of the Group.
   */
  public GroupAdd(String name, @Nullable String externalId) {
    this.name = name;
    this.externalId = externalId;
  }

  /**
   * Gets the name of the Group.
   *
   * @return The name of the Group.
   */
  public String name() {
    return name;
  }

  /**
   * Gets the external identifier of the Group.
   *
   * @return The external identifier of the Group.
   */
  @Nullable
  public String externalId() {
    return externalId;
  }
}
