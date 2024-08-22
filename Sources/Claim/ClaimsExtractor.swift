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
import SwiftyJSON

public typealias ClaimExtractorResult = (digestsFoundOnPayload: [DigestType], recreatedClaims: JSON)

public class ClaimExtractor {

  // MARK: - Properties

  var digestsOfDisclosuresDict: [DisclosureDigest: Disclosure]

  // MARK: - Lifecycle

  public init(digestsOfDisclosuresDict: [DisclosureDigest: Disclosure]) {
    self.digestsOfDisclosuresDict = digestsOfDisclosuresDict
  }

  // MARK: - Methods

  public func findDigests(payload json: JSON, disclosures: [Disclosure]) throws -> ClaimExtractorResult {
    var json = json
    json.dictionaryObject?.removeValue(forKey: Keys.sdAlg.rawValue)
    var foundDigests: [DigestType] = []

    // try to find sd keys on the top level
    if let sdArray = json[Keys.sd.rawValue].array, !sdArray.isEmpty {
      var sdArray = sdArray.compactMap(\.string)
      // try to find matching digests in order to be replaced with the value
      while true {
        let (updatedSdArray, foundDigest) = sdArray.findAndRemoveFirst(from: digestsOfDisclosuresDict.compactMap({$0.key}))
        if let foundDigest,
           let foundDisclosure = digestsOfDisclosuresDict[foundDigest]?.base64URLDecode()?.objectProperty {
          json[Keys.sd.rawValue].arrayObject = updatedSdArray

          guard !json[foundDisclosure.key].exists() else {
            throw SDJWTVerifierError.nonUniqueDisclosures
          }

          json[foundDisclosure.key] = foundDisclosure.value
          foundDigests.append(.object(foundDigest))

        } else {
          json.dictionaryObject?.removeValue(forKey: Keys.sd.rawValue)
          break
        }
      }

    }

    // Loop through the inner JSON data
    for (key, subJson): (String, JSON) in json {
      if !subJson.dictionaryValue.isEmpty {
        let foundOnSubJSON = try self.findDigests(payload: subJson, disclosures: disclosures)
        // if found swap the disclosed value with the found value
        foundDigests += foundOnSubJSON.digestsFoundOnPayload
        json[key] = foundOnSubJSON.recreatedClaims
      } else if !subJson.arrayValue.isEmpty {
        for (index, object) in subJson.arrayValue.enumerated() {
          if object[Keys.dots.rawValue].exists() {
            if let foundDisclosedArrayElement = digestsOfDisclosuresDict[object[Keys.dots].stringValue]?
              .base64URLDecode()?
              .arrayProperty {

              foundDigests.appendOptional(.array(object[Keys.dots].stringValue))
              // If the object is a json we should further process it and replace
              // the element with the value found in the disclosure
              // Example https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-example-3-complex-structure
              if let ifHasNested = try? findDigests(payload: foundDisclosedArrayElement, disclosures: disclosures),
                 !ifHasNested.digestsFoundOnPayload.isEmpty {
                foundDigests += ifHasNested.digestsFoundOnPayload
                json[key].arrayObject?[index] = ifHasNested.recreatedClaims
              }
            }
          }
        }
      }
    }

    return (foundDigests, json)
  }
}
