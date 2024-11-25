/*
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

//
//  TestSignedSDJWTFilterDisclosures.swift
//

import XCTest
@testable import eudi_lib_sdjwt_swift

final class TestSignedSDJWTFilterDisclosures: XCTestCase {
    
    private func standardDigestCreator() -> DigestCreator {
        return DigestCreator(hashingAlgorithm: SHA256Hashing())
    }
    
    private func standardDisclosures() -> [Disclosure] {
        return [
            "WyJVM1hmUkdlTlJtRXpZbkhIRVh2dkVBIiwiaXNzdWluZ19jb3VudHJ5IiwiRCJd",
            "WyItZ3pUbkd5cU16U3ExMGdHc2Y4bzFBIiwiaXNzdWluZ19hdXRob3JpdHkiLCJEIl0",
            "WyJjSmdabWJlVlYycE14b0xQQ01kYWhRIiwic291cmNlX2RvY3VtZW50X3R5cGUiLCJpZF9jYXJkIl0",
            "WyI2OGRWeXAwSXZIYy04VG9NdFJFbTh3IiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0",
            "WyIwM3RRTlFjRS10bUVzY19ZVFFMemRRIiwiZmFtaWx5X25hbWUiLCJNVVNURVJNQU5OIl0",
            "WyI0TnRwd0tXbDA2Tk5nVXBJMnZhaVNnIiwiYmlydGhkYXRlIiwiMTk2NC0wOC0xMiJd",
            "WyJGUjhFWS1GTzV2WVhmSXIxeEplWldnIiwiYWdlX2luX3llYXJzIiwiNjAiXQ",
            "WyJHYV9xNzdZa25HSlg1cHRrd0RBa2pnIiwiYWdlX2JpcnRoX3llYXIiLCIxOTY0Il0",
            "WyJzWi05dTNoSm9pcEY2NnE5bUtzQlBBIiwiYmlydGhfZmFtaWx5X25hbWUiLCJHQUJMRVIiXQ",
            "WyJEZWxDRXh3cFNkdnFSdEN3M0RpNG5RIiwibG9jYWxpdHkiLCJCRVJMSU4iXQ",
            "WyJfaFlGTDAyaFhlMXUwWXBEbVBJQzF3IiwicGxhY2Vfb2ZfYmlydGgiLHsiX3NkIjpbIlEzdkxwTHNoZGRCdFNDZzFpLTVPeEtZRWlObS1wSk5BRjhPNGJDaURweTAiXX1d",
            "WyJnYVdqdnUzSGlOeWRRejBPemZ2WTJRIiwiZm9ybWF0dGVkIiwiSEVJREVTVFJBU1NFIDE3XG41MTE0NyBLw5ZMTlxuRCJd",
            "WyJvWl9vMElBOUcycVNmWU1JVlVpY2pnIiwiY291bnRyeSIsIkQiXQ",
            "WyJlVHFxNXlNMW9jM2R0dm1WTnZvRk9nIiwibG9jYWxpdHkiLCJLw5ZMTiJd",
            "WyJWRk1jRC1rUmRscXdvakMyNmVGN2lRIiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd",
            "WyJWZkRJLTQzNFVBUXptWmJyTmJWLXlRIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkFTU0UgMTciXQ",
            "WyJmMUJfX0RzOFBTT1lPUGp3NExNT3ZRIiwiYWRkcmVzcyIseyJfc2QiOlsiOUNfTlRUREhrR2lGd0xkeG1ZcFFVUWJYN09HWWNJcHd6RkV6ekpjU1RNWSIsIkFXYmlITlhhTWs2N05vSlFldjV2U3pPQVBYakd0SDVxajBFOFV5NzhDUG8iLCJELTBreWdrZnc2c2RFZHU2X3FsblhRQlZ3X1BsWFhrSFRrWTJHTlNnMFI4IiwiRzBleDBpdFUxVVRCbVZNRDhldGc2elZJTEJLbTB3MjQwa3dOVGxPaTlqdyIsImd1QUZwYUx4SzkybzVmd3F3WTd1YkFhem56eV9xSG8wZU8wVnlZWmNHUjAiXX1d"
        ]
    }
    
    private func depth3Disclosures() -> [Disclosure] {
        return [
            "WyJWOTZUbG5RV0xTQThWTlBfZ1dsY1ZnIiwibnVtYmVyIiwiNDEiXQo",
            "WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K",
            "WyI5dzJkYV9ieXNhcm4yZGpnZ051eUhRIiwic3RyZWV0Iix7Il9zZCI6WyJKM2l3TjhCR2lfSVVfOU9YdllWYS1FM0o2U1F1QjdGN3hyVnpRM1puTDJrIiwibDdOSzdwYVdjb3ktRjVmNnZETVRWcWRtNk1qRG1uNHh3OExQZHdzREszQSJdfV0K",
            "WyJnNVN3b2hVYk9raUh5czliMktvZlFRIiwiYWRkcmVzcyIseyJfc2QiOlsieXh1S3dybk9RREpieHVoalB2RWs2Qi1NMW5WR2pWcHMzRzgtYzB0VkEtOCJdfV0K"
        ]
    }
    
    

    func testFilterSDJWTDisclosures() throws {
        
        let claimNames :[String] = [
            "family_name",
            "given_name",
            "birthdate",
            "age_equal_or_over.18",
            "age_in_years",
            "age_birth_year",
            "birth_family_name",
            "place_of_birth",
            "address",
            "nationalities",
            "issuing_authority",
            "issuing_country",
            "source_document_type",
        ]
        
        let disclosures = standardDisclosures()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, disclosures.count)
    }
    
    func testFilterSDJWTDisclosuresOnlyGivenName() throws {
        
        let claimNames :[String] = [
            "given_name"
        ]
        
        let disclosures = standardDisclosures()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 1)
        XCTAssertEqual("WyI2OGRWeXAwSXZIYy04VG9NdFJFbTh3IiwiZ2l2ZW5fbmFtZSIsIkVSSUtBIl0", result.first)
    }
    
    func testFilterSDJWTDisclosuresOnlyAdressFields() throws {
        
        let claimNames :[String] = [
            "address"
        ]
        
        let disclosures = standardDisclosures()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 6)
        XCTAssertTrue(result.contains("WyJmMUJfX0RzOFBTT1lPUGp3NExNT3ZRIiwiYWRkcmVzcyIseyJfc2QiOlsiOUNfTlRUREhrR2lGd0xkeG1ZcFFVUWJYN09HWWNJcHd6RkV6ekpjU1RNWSIsIkFXYmlITlhhTWs2N05vSlFldjV2U3pPQVBYakd0SDVxajBFOFV5NzhDUG8iLCJELTBreWdrZnc2c2RFZHU2X3FsblhRQlZ3X1BsWFhrSFRrWTJHTlNnMFI4IiwiRzBleDBpdFUxVVRCbVZNRDhldGc2elZJTEJLbTB3MjQwa3dOVGxPaTlqdyIsImd1QUZwYUx4SzkybzVmd3F3WTd1YkFhem56eV9xSG8wZU8wVnlZWmNHUjAiXX1d"))
    }
    
    func testFilterSDJWTDisclosuresOnlySomeAdressFields() throws {
        
        let claimNames :[String] = [
            "address.street_address",
            "address.postal_code",
            "address.locality"
        ]
        
        let disclosures = standardDisclosures()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 4)
        
        //street_address
        XCTAssertTrue(result.contains("WyJWZkRJLTQzNFVBUXptWmJyTmJWLXlRIiwic3RyZWV0X2FkZHJlc3MiLCJIRUlERVNUUkFTU0UgMTciXQ"))
        
        //postal_code
        XCTAssertTrue(result.contains("WyJWRk1jRC1rUmRscXdvakMyNmVGN2lRIiwicG9zdGFsX2NvZGUiLCI1MTE0NyJd"))
        
        //locality
        XCTAssertTrue(result.contains("WyJlVHFxNXlNMW9jM2R0dm1WTnZvRk9nIiwibG9jYWxpdHkiLCJLw5ZMTiJd"))
        
        //address
        XCTAssertTrue(result.contains("WyJmMUJfX0RzOFBTT1lPUGp3NExNT3ZRIiwiYWRkcmVzcyIseyJfc2QiOlsiOUNfTlRUREhrR2lGd0xkeG1ZcFFVUWJYN09HWWNJcHd6RkV6ekpjU1RNWSIsIkFXYmlITlhhTWs2N05vSlFldjV2U3pPQVBYakd0SDVxajBFOFV5NzhDUG8iLCJELTBreWdrZnc2c2RFZHU2X3FsblhRQlZ3X1BsWFhrSFRrWTJHTlNnMFI4IiwiRzBleDBpdFUxVVRCbVZNRDhldGc2elZJTEJLbTB3MjQwa3dOVGxPaTlqdyIsImd1QUZwYUx4SzkybzVmd3F3WTd1YkFhem56eV9xSG8wZU8wVnlZWmNHUjAiXX1d"))
    }

    
    func testFilterSDJWTDisclosuresDepth3() throws {
        
        let claimNames :[String] = [
            "address.street.number",
            "address.street.city",
        ]
        
        let disclosures = depth3Disclosures()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 4)
        
        //number
        XCTAssertTrue(result.contains("WyJWOTZUbG5RV0xTQThWTlBfZ1dsY1ZnIiwibnVtYmVyIiwiNDEiXQo"))
        
        //city
        XCTAssertTrue(result.contains("WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K"))
        
    }
    
    func testFilterSDJWTDisclosuresDepth3Reversed() throws {
        
        let claimNames :[String] = [
            "address.street.number",
        ]
        
        var disclosures = depth3Disclosures()
        disclosures.reverse()
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 3)
        
        //number
        XCTAssertTrue(result.contains("WyJWOTZUbG5RV0xTQThWTlBfZ1dsY1ZnIiwibnVtYmVyIiwiNDEiXQo"))
        
        //city
        XCTAssertFalse(result.contains("WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K"))
        
    }
    
    func testFilterSDJWTDisclosuresDepth3AndDecoyHash() throws {
        
        let claimNames :[String] = [
            "address.street.number",
            "address.street.city",
        ]
        
        var disclosures = depth3Disclosures()
        if let index = disclosures.firstIndex(of: "WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K") { //city
            disclosures.remove(at: index)
        }
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 3)
        
        //number
        XCTAssertTrue(result.contains("WyJWOTZUbG5RV0xTQThWTlBfZ1dsY1ZnIiwibnVtYmVyIiwiNDEiXQo"))
        
        //city
        XCTAssertFalse(result.contains("WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K"))
        
    }
    
    func testFilterSDJWTDisclosuresMissingStructredDisclosure() throws {
        
        let claimNames :[String] = [
            "address.street.number",
            "address.street.city",
        ]
        
        var disclosures = depth3Disclosures()
        if let index = disclosures.firstIndex(of: "WyI5dzJkYV9ieXNhcm4yZGpnZ051eUhRIiwic3RyZWV0Iix7Il9zZCI6WyJKM2l3TjhCR2lfSVVfOU9YdllWYS1FM0o2U1F1QjdGN3hyVnpRM1puTDJrIiwibDdOSzdwYVdjb3ktRjVmNnZETVRWcWRtNk1qRG1uNHh3OExQZHdzREszQSJdfV0K") { //street
            disclosures.remove(at: index)
        }
        
        let result = SignedSDJWT.filterSDJWTDisclosures(disclosures, claimNames: claimNames, digestCreator: standardDigestCreator())
        
        XCTAssertEqual(result.count, 1)
        
        //number
        XCTAssertFalse(result.contains("WyJWOTZUbG5RV0xTQThWTlBfZ1dsY1ZnIiwibnVtYmVyIiwiNDEiXQo"))
        
        //city
        XCTAssertFalse(result.contains("WyJtVHJNS19GYWVLZHRzMDNkelpaRWlnIiwiY2l0eSIsIk1haW56Il0K"))
        
    }
    
}
