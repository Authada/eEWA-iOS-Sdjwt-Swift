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
import JSONWebKey
import JSONWebSignature
import JSONWebToken
import SwiftyJSON

public typealias KBJWT = JWT

struct SDJWT {

  // MARK: - Properties

  public internal(set) var jwt: JWT
  public internal(set) var disclosures: [Disclosure]
  public internal(set) var kbJwt: JWT?

  // MARK: - Lifecycle

  init(jwt: JWT, disclosures: [Disclosure], kbJWT: KBJWT?) throws {
    self.jwt = jwt
    self.disclosures = disclosures
    self.kbJwt = kbJWT
  }

  func extractDigestCreator() throws -> DigestCreator {
    if jwt.payload[Keys.sdAlg.rawValue].exists() {
      let stringValue = jwt.payload[Keys.sdAlg.rawValue].stringValue
      let algorithIdentifier = HashingAlgorithmIdentifier.allCases.first(where: {$0.rawValue == stringValue})
      guard let algorithIdentifier else {
        throw SDJWTVerifierError.missingOrUnknownHashingAlgorithm
      }
      return DigestCreator(hashingAlgorithm: algorithIdentifier.hashingAlgorithm())
    } else {
      throw SDJWTVerifierError.missingOrUnknownHashingAlgorithm
    }
  }

  func recreateClaims() throws -> ClaimExtractorResult {
    let digestCreator = try extractDigestCreator()
    var digestsOfDisclosuresDict = [DisclosureDigest: Disclosure]()
    for disclosure in self.disclosures {
      let hashed = digestCreator.hashAndBase64Encode(input: disclosure)
      if let hashed {
        digestsOfDisclosuresDict[hashed] = disclosure
      } else {
        throw SDJWTVerifierError.failedToCreateVerifier
      }
    }

    return try ClaimExtractor(digestsOfDisclosuresDict: digestsOfDisclosuresDict)
      .findDigests(payload: jwt.payload, disclosures: disclosures)
  }
}

public struct SignedSDJWT {

  // MARK: - Properties

  public let jwt: JWS
  public internal(set) var disclosures: [Disclosure]
  public internal(set) var kbJwt: JWS?

  var delineatedCompactSerialisation: String {
    let separator = "~"
      let input = ([jwt.compactSerialization] + disclosures).reduce("") { $0.isEmpty ? $1 : $0 + separator + $1 } + separator
    return DigestCreator()
      .hashAndBase64Encode(
        input: input
    ) ?? ""
  }

  // MARK: - Lifecycle

  init(
    serializedJwt: String,
    disclosures: [Disclosure],
    serializedKbJwt: String?
  ) throws {
    self.jwt = try JWS(jwsString: serializedJwt)
    self.disclosures = disclosures
    self.kbJwt = try? JWS(jwsString: serializedKbJwt ?? "")
  }

  private init?<KeyType>(sdJwt: SDJWT, issuersPrivateKey: KeyType) {
    // Create a Signed SDJWT with no key binding
    guard let signedJwt = try? SignedSDJWT.createSignedJWT(key: issuersPrivateKey, jwt: sdJwt.jwt) else {
      return nil
    }

    self.jwt = signedJwt
    self.disclosures = sdJwt.disclosures
    self.kbJwt = nil
  }

  private init?<KeyType>(signedSDJWT: SignedSDJWT, kbJWT: JWT, holdersPrivateKey: KeyType) {
    // Assume that we have a valid signed jwt from the issuer
    // And key exchange has been established
    // signed SDJWT might contain or not the cnf claim

    self.jwt = signedSDJWT.jwt
    self.disclosures = signedSDJWT.disclosures
    let signedKBJwt = try? SignedSDJWT.createSignedJWT(key: holdersPrivateKey, jwt: kbJWT)
    self.kbJwt = signedKBJwt
  }

  // MARK: - Methods

  // expose static func initializers to distinguish between 2 cases of
  // signed SDJWT creation

  static func nonKeyBondedSDJWT<KeyType>(sdJwt: SDJWT, issuersPrivateKey: KeyType) throws -> SignedSDJWT {
    try .init(sdJwt: sdJwt, issuersPrivateKey: issuersPrivateKey) ?? {
      throw SDJWTVerifierError.invalidJwt
    }()
  }

  static func keyBondedSDJWT<KeyType>(signedSDJWT: SignedSDJWT, kbJWT: JWT, holdersPrivateKey: KeyType) throws -> SignedSDJWT {
    try .init(signedSDJWT: signedSDJWT, kbJWT: kbJWT, holdersPrivateKey: holdersPrivateKey) ?? {
      throw SDJWTVerifierError.invalidJwt
    }()
  }

  private static func createSignedJWT<KeyType>(key: KeyType, jwt: JWT) throws -> JWS {
    try jwt.sign(key: key)
  }

  func disclosuresToPresent(disclosures: [Disclosure]) -> Self {
    var updated = self
    updated.disclosures = disclosures
    return updated
  }

  func toSDJWT() throws -> SDJWT {
      if let kbJwtHeader = kbJwt?.protectedHeader,
       let kbJWtPayload = try? kbJwt?.payloadJSON() {
      return try SDJWT(
        jwt: JWT(header: jwt.protectedHeader, payload: jwt.payloadJSON()),
        disclosures: disclosures,
        kbJWT: JWT(header: kbJwtHeader, kbJwtPayload: kbJWtPayload))
    }

    return try SDJWT(
      jwt: JWT(header: jwt.protectedHeader, payload: jwt.payloadJSON()),
      disclosures: disclosures,
      kbJWT: nil)
  }

  func extractHoldersPublicKey() throws -> JWK {
    let payloadJson = try self.jwt.payloadJSON()
    let jwk = payloadJson[Keys.cnf]["jwk"]

    guard jwk.exists() else {
      throw SDJWTVerifierError.keyBindingFailed(description: "Failled to find holders public key")
    }

    guard let jwkObject = try? JSONDecoder.jwt.decode(JWK.self, from: jwk.rawData()) else {
      throw SDJWTVerifierError.keyBindingFailed(description: "failled to extract key type")
    }

    return jwkObject
  }

    
    static func allDisclosures(from structuredDisclosures:[Disclosure:[Any]], for disclosure:Disclosure) -> Set<Disclosure> {
        var results :Set<Disclosure>  = []
        
        if let disArray = structuredDisclosures[disclosure] {
            results.insert(disclosure)
            for element in disArray {
                
                if let subDisclosure = element as? Disclosure {
                    results.insert(subDisclosure)
                }
                else if let subStructuredDisclosures = element as? [Disclosure:[Any]] {
                    
                    if let allKeys = Array(subStructuredDisclosures.keys) as? [Disclosure] {
                        for keyDisclosure in allKeys {
                            let subDisclosures = allDisclosures(from: subStructuredDisclosures, for: keyDisclosure)
                            results.formUnion(subDisclosures)
                        }
                    }
                }
            }
        }
        
        return results
    }
    
    static func filterSDJWTDisclosures(_ disclosures:[Disclosure], claimNames:[String], digestCreator:DigestCreator) -> [Disclosure] {
        
        var disclosureHashDict :[String:Disclosure] = [:]
        
        var claimArrayDisclosureDict : [Disclosure:[Any]] = [:]
        
        var disclosureArrayElementsDict :[String:Disclosure] = [:]
        var disclosureObjectElementsDict :[String:Disclosure] = [:]
        
        var disclosureContainingSDElementsDict :[String:Disclosure] = [:]
        var disclosureContainingDotsElementsDict :[String:Disclosure] = [:]
        
        //First Pass to build up usefull data structures
        for c in disclosures {
            let hash = digestCreator.hashAndBase64Encode(input: c) ?? "nil"
            disclosureHashDict[hash] = c
            
            let jsonString = c.base64URLDecode() ?? "?"
                        
            if let claimArray = JSON(parseJSON: jsonString).arrayObject {
                claimArrayDisclosureDict[c] = claimArray
                
                if claimArray.count == 3 {
                    //Disclosures for Object Properties
                    if claimArray[1] is String {
                        disclosureObjectElementsDict[hash] = c
                        
                        let claimValue = claimArray[2]
                        if let valueDict = claimValue as? Dictionary<AnyHashable,Any> {
                            if valueDict["_sd"] is [String] {
                                disclosureContainingSDElementsDict[hash] = c
                            }
                        }
                        if let valueArray = claimValue as? Array<Any> {
                            for value in valueArray {
                                if let valueDict = value as? Dictionary<AnyHashable,Any> {
                                    if valueDict["..."] is String {
                                        disclosureContainingDotsElementsDict[hash] = c
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                else if claimArray.count == 2 {
                    //Disclosures for Array Elements
                    disclosureArrayElementsDict[hash] = c
                }
            }
        }
        
        var leafDisclosures = disclosures
        var structuredDisclosures : [Disclosure:[Any]] = [:]
        
        if (disclosureContainingSDElementsDict.count > 0) {
            var sdDisclosureDict = disclosureContainingSDElementsDict
            
            for keyValuePair in sdDisclosureDict {
                let disclosureWithSD = keyValuePair.value
                if let index = leafDisclosures.firstIndex(of: disclosureWithSD) {
                    leafDisclosures.remove(at: index)
                }
            }
            
            //var missingHashMatches :[Disclosure:[String:Disclosure]] = [:]
            
            //Build structuredDisclosures
            var valuesChoosen = false
            repeat {
                
                valuesChoosen = false
                for (hash, disclosure) in sdDisclosureDict {
                    
                    var chooseValue = true
                                        
                    structuredDisclosures[disclosure] = []
                    
                    if let claimArray = claimArrayDisclosureDict[disclosure], claimArray.count == 3 {
                        let claimValue = claimArray[2]
                        if let valueDict = claimValue as? Dictionary<AnyHashable,Any> {
                            if let hashValues = valueDict["_sd"] as? [String] {
                                for hash in hashValues {
                                    if let disclosureForHash = disclosureHashDict[hash] { //if no disclosureForHash found it is a decoy hash -> ignore
                                        
                                        if leafDisclosures.firstIndex(of: disclosureForHash) != nil {
                                            
                                            if var subDisclosures = structuredDisclosures[disclosure] {
                                                subDisclosures.append(disclosureForHash)
                                                structuredDisclosures[disclosure] = subDisclosures
                                            }
                                        }
                                        else {
                                            if let match = structuredDisclosures[disclosureForHash] {
                                                structuredDisclosures.removeValue(forKey: disclosureForHash)
                                                
                                                if var subDisclosures = structuredDisclosures[disclosure] {
                                                    subDisclosures.append([disclosureForHash:match])
                                                    structuredDisclosures[disclosure] = subDisclosures
                                                }
                                            }
                                            else {
                                                //kein match
                                                chooseValue = false
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    
                    if chooseValue {
                        sdDisclosureDict.removeValue(forKey: hash)
                        valuesChoosen = true
                        break
                    }
                }
            } while (sdDisclosureDict.count > 0 && valuesChoosen)
        }
                
        var disclosuresToPresent :Set<Disclosure> = []
        
        //Search final disclosures
        for claimNameToFind in claimNames {
            let isTreeStructureClaim = claimNameToFind.contains(".")
            
            if (!isTreeStructureClaim) {
                //First check simple leaf disclosures
                for c in leafDisclosures {
                    if let claimArray = claimArrayDisclosureDict[c], claimArray.count == 3, let claimName = claimArray[1] as? String {
                        if claimName == claimNameToFind {
                            disclosuresToPresent.insert(c)
                        }
                    }
                }
                for keyValuePair in structuredDisclosures {
                    let c = keyValuePair.key
                    if let claimArray = claimArrayDisclosureDict[c], claimArray.count == 3, let claimName = claimArray[1] as? String {
                        if claimName == claimNameToFind {
                            let allRelevantDisclosures = allDisclosures(from: structuredDisclosures, for: c)
                            disclosuresToPresent.formUnion(allRelevantDisclosures)
                        }
                    }
                }
            }
            else {
                let components = claimNameToFind.components(separatedBy: ".")
                var currentStructuredDisclosures:[Any] = [structuredDisclosures]
                
                for i in 0..<components.count {
                    let searchClaimName = components[i]
                                        
                    for element in currentStructuredDisclosures {
                        if let disclosure = element as? Disclosure {
                            if let claimArray = claimArrayDisclosureDict[disclosure], claimArray.count == 3, let claimName = claimArray[1] as? String, claimName == searchClaimName {
                                //Found disclosure
                                if i == components.count-1 {
                                    disclosuresToPresent.insert(disclosure)
                                }
                                break
                            }
                        }
                        else if let disclosuresStructured = element as? [Disclosure:[Any]] {
                            for keyValuePair in disclosuresStructured {
                                let c = keyValuePair.key
                                if let claimArray = claimArrayDisclosureDict[c], claimArray.count == 3, let claimName = claimArray[1] as? String, claimName == searchClaimName {
                                    //Found disclosre structure
                                    if i == components.count-1 {
                                        let allMatchingDisclosures = allDisclosures(from: disclosuresStructured, for: c)
                                        disclosuresToPresent.formUnion(allMatchingDisclosures)
                                    }
                                    else {
                                        currentStructuredDisclosures = keyValuePair.value
                                        disclosuresToPresent.insert(c)
                                    }
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
        
        return Array(disclosuresToPresent)
    }
    
  public func filteredDisclosures(with claimNames:[String]) -> [Disclosure]? {
      if let dCreator = try? self.toSDJWT().extractDigestCreator() {
          return SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: dCreator)
      }
      return nil
  }
}

extension SignedSDJWT {
  func serialised(serialiser: (SignedSDJWT) -> (SerialiserProtocol)) throws -> Data {
    serialiser(self).data
  }

  func serialised(serialiser: (SignedSDJWT) -> (SerialiserProtocol)) throws -> String {
    serialiser(self).serialised
  }
}

extension SignedSDJWT {
  public func recreateClaims() throws -> ClaimExtractorResult {
    return try self.toSDJWT().recreateClaims()
  }
}
