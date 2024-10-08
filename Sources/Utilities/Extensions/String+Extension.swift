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

extension String {
  func base64ToUTF8() -> String? {
    guard let data = Data(base64Encoded: self) else {
      return nil
    }
    return String(data: data, encoding: .utf8)
  }

  func toBase64URLEncoded() -> String? {
    let data = self.data(using: .utf8)
    return data?.base64URLEncode()
  }

  func convertURLEncodedBase64ToData() -> Data? {
    // Decode URL-encoded string
    guard let decodedURLString = self.removingPercentEncoding else {
      return nil
    }

    // Convert base64 string to Data
    guard let data = Data(base64Encoded: decodedURLString) else {
      return nil
    }

    return data
  }

  func base64URLDecode() -> String? {
    var base64 = self
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")

    // Padding the string with '=' characters to make its length a multiple of 4
    let paddingLength = 4 - base64.count % 4
    if paddingLength < 4 {
      base64.append(contentsOf: String(repeating: "=", count: paddingLength))
    }

    if let data = Data(base64Encoded: base64) {
      return String(data: data, encoding: .utf8)
    }

    return nil
  }
}
