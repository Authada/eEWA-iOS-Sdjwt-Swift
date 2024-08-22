/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modified by AUTHADA GmbH
 * Copyright (c) 2024 AUTHADA GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation

@resultBuilder
public enum SDJWTBuilder {
  public static func buildBlock(_ elements: [ClaimRepresentable]) -> SdElement {
    return .object(
      elements.reduce(into: [:]) { partialResult, claim in
        partialResult[claim.key] = claim.value
      }
    )
  }

  public static func buildBlock(_ elements: ClaimRepresentable...) -> SdElement {
    self.buildBlock(elements.map({$0}))
  }

  public static func buildBlock(_ elements: ClaimRepresentable?...) -> SdElement {
    self.buildBlock(elements.compactMap({$0}))
  }

  public static func build(@SDJWTBuilder builder: () throws -> SdElement) rethrows -> SDJWTObject {
    return try builder().asObject ?? {
      throw SDJWTError.encodingError
    }()
  }
}
