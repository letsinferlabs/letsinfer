import Foundation

struct EnrollmentClient {
    let identityStore: NodeIdentityStore

    func enroll(
        request: NodeAddRequest,
        provisional: ProvisionalNodeIdentity,
        memberName: String,
        memberAddress: String
    ) async throws -> MembershipRecord {
        guard let baseURL = URL(string: request.mainEndpoint) else {
            throw NodeError.invalidData("Main node endpoint is invalid")
        }
        let client = PinnedHTTPSClient(
            expectedCertificateSHA256: request.mainCertificateSHA256
        )
        let challengeURL = baseURL.appending(
            path: "node/v1/enroll/\(request.inviteID)"
        )
        let challengeObject = try await client.request(
            method: "GET",
            url: challengeURL
        )
        let challenge = try EnrollmentChallenge.parse(challengeObject)
        guard challenge.siteID == request.mainNodeID,
              challenge.inviteID == request.inviteID,
              challenge.mode == "lan",
              challenge.coordinatorCertificateSHA256 == request.mainCertificateSHA256
        else {
            throw NodeError.invalidData("Membership challenge changed the selected main node")
        }
        let transcript: [String: Any] = [
            "contract": "letsinfer-child-enrollment-v1",
            "site_id": challenge.siteID,
            "invite_id": challenge.inviteID,
            "nonce": challenge.nonce,
            "member_id": provisional.memberID,
            "member_name": memberName,
            "member_address": memberAddress,
            "member_public_key_sha256": try identityStore.publicKeySHA256(),
            "installation_id": provisional.installationID,
            "installation_created_at_unix": provisional.createdAtUnix,
        ]
        let proof = try identityStore.sign(CanonicalJSON.data(transcript))
            .base64EncodedString()
        let payload: [String: Any] = [
            "protocol": NodeProtocol.control,
            "invite_id": request.inviteID,
            "code": request.membershipCode,
            "member_id": provisional.memberID,
            "member_name": memberName,
            "member_address": memberAddress,
            "member_public_key": try identityStore.publicKeyPEM(),
            "installation_id": provisional.installationID,
            "installation_created_at_unix": provisional.createdAtUnix,
            "proof_signature": proof,
        ]
        let response = try await client.request(
            method: "POST",
            url: baseURL.appending(path: "node/v1/enroll"),
            object: payload
        )
        let membership = try MembershipRecord.parse(
            response: response,
            request: request,
            provisional: provisional,
            identityStore: identityStore
        )
        try identityStore.save(membership: membership)
        return membership
    }
}
