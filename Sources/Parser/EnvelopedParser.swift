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

public class EnvelopedParser: ParserProtocol {

  // MARK: - Properties

  var sdJwt: SignedSDJWT

  // MARK: - Lifecycle

  public init(serialiserProtocol: SerialiserProtocol) throws {
    let jsonDecoder = JSONDecoder()
    let envelopedJwt = try jsonDecoder.decode(EnvelopedJwt.self, from: serialiserProtocol.data)
    let compactParser = CompactParser(serialisedString: envelopedJwt.sdJwt)
    self.sdJwt = try compactParser.getSignedSdJwt()
  }

  public init(data: Data) throws {
    let jsonDecoder = JSONDecoder()
    let envelopedJwt = try jsonDecoder.decode(EnvelopedJwt.self, from: data)
    let compactParser = CompactParser(serialisedString: envelopedJwt.sdJwt)
    self.sdJwt = try compactParser.getSignedSdJwt()
  }

  // MARK: - Methods

  public func getSignedSdJwt() throws -> SignedSDJWT {
    return sdJwt
  }

}

public struct EnvelopedJwt: Codable {
    let aud: String
    let iat: Int
    let nonce: String
    let sdJwt: String

    enum CodingKeys: String, CodingKey {
        case aud
        case iat
        case nonce
        case sdJwt = "_sd_jwt"
    }
}
