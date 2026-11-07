use super::*;

#[tokio::test]
async fn hostile_device_fingerprint_is_rejected_before_approval_is_sent() {
    let new_device = beebeeb_core::device_link::NewDeviceLink::generate([4; 16]).unwrap();
    let qr = new_device.qr();
    let transport = Arc::new(ScriptedTransport::json(
        200,
        format!(
            r#"{{"id":"link","session_id":"{}","public_key":"{}","device_name":"reported","reported_by_device":true,"status":"pending","expires_at":"2099-01-01T00:00:00Z"}}"#,
            STANDARD.encode(qr.session_id()),
            STANDARD.encode([9u8; 32])
        )
        .into_bytes(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    client.set_authentication("token", "account").unwrap();
    client
        .set_session_key_for_test(Arc::new(MasterKey::from_bytes([7; 32])))
        .unwrap();

    let result = client.approve_device_link("link", &qr, new_device.typed_code()).await;

    assert!(matches!(result, Err(DeviceError::Crypto)));
    assert_eq!(transport.request_count(), 1);
}

#[tokio::test]
async fn wrong_typed_code_consumes_the_device_link_attempt() {
    let (client, transport, mut pending, public_key) = started_link().await;
    let qr = pending.qr().unwrap();
    let mut wrong_code = pending.typed_code().unwrap().as_bytes().to_vec();
    wrong_code[0] = if wrong_code[0] == b'2' { b'3' } else { b'2' };
    let wrong_code = String::from_utf8(wrong_code).unwrap();
    let sealed = beebeeb_core::device_link::seal_for_new_device(
        &qr,
        &public_key,
        &wrong_code,
        AccountKeyMaterial::from_master_key(MasterKey::from_bytes([7; 32])),
    )
    .unwrap();
    transport.push_json(200, approved_result(&sealed));
    transport.push_json(200, approved_result(&sealed));

    assert!(matches!(
        client.poll_device_link(&mut pending).await,
        Err(DeviceError::Crypto)
    ));
    assert!(matches!(
        client.poll_device_link(&mut pending).await,
        Err(DeviceError::NotPending)
    ));
}

#[tokio::test]
async fn approved_device_link_cannot_be_opened_twice() {
    let (client, transport, mut pending, public_key) = started_link().await;
    let qr = pending.qr().unwrap();
    let code = pending.typed_code().unwrap().to_owned();
    let sealed = beebeeb_core::device_link::seal_for_new_device(
        &qr,
        &public_key,
        &code,
        AccountKeyMaterial::from_master_key(MasterKey::from_bytes([7; 32])),
    )
    .unwrap();
    transport.push_json(200, approved_result(&sealed));
    transport.push_json(200, approved_result(&sealed));

    assert!(matches!(
        client.poll_device_link(&mut pending).await.unwrap(),
        DeviceLinkPoll::Approved(_)
    ));
    assert!(matches!(
        client.poll_device_link(&mut pending).await,
        Err(DeviceError::NotPending)
    ));
}

#[tokio::test]
async fn typed_only_device_link_uses_the_existing_result_shape_once() {
    let (client, transport, pending, public_key) = started_link().await;
    let id = pending.id().to_owned();
    let code = pending.typed_code().unwrap().to_owned();
    let session_id = STANDARD.encode(pending.qr().unwrap().session_id());
    let (new_device, new_device_message) = pending.begin_typed_path().unwrap();

    transport.push_json(200, br#"{"ok":true}"#.to_vec());
    client
        .send_device_link_pake(
            &id,
            beebeeb_api::proposed::DeviceLinkRole::NewDevice,
            &new_device_message,
        )
        .await
        .unwrap();
    transport.push_json(200, pending_link_detail(&id, &session_id, &public_key));
    let (approver, approver_message) = client.begin_typed_device_approval(&id, &code).await.unwrap();
    transport.push_json(200, br#"{"ok":true}"#.to_vec());
    client
        .send_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::Approver, &approver_message)
        .await
        .unwrap();
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "status": "ready",
            "message": STANDARD.encode(&new_device_message),
        }))
        .unwrap(),
    );
    let relayed_new_device_message = client
        .get_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::Approver)
        .await
        .unwrap()
        .unwrap();
    assert!(transport.requests().last().unwrap().path().ends_with("?role=approver"));

    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "status": "ready",
            "message": STANDARD.encode(&approver_message),
        }))
        .unwrap(),
    );
    let relayed_approver_message = client
        .get_device_link_pake(&id, beebeeb_api::proposed::DeviceLinkRole::NewDevice)
        .await
        .unwrap()
        .unwrap();
    assert!(
        transport
            .requests()
            .last()
            .unwrap()
            .path()
            .ends_with("?role=new_device")
    );

    transport.push_json(200, br#"{"ok":true}"#.to_vec());
    client
        .approve_typed_device_link(approver, &relayed_new_device_message)
        .await
        .unwrap();
    let approval = transport.requests().pop().unwrap();
    let approval: serde_json::Value = serde_json::from_slice(approval.body()).unwrap();
    assert!(approval.get("approver_public").is_none());

    let mut receiver = new_device.finish(&relayed_approver_message).unwrap();
    transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "status": "approved",
            "nonce": approval["nonce"],
            "ciphertext": approval["ciphertext"],
        }))
        .unwrap(),
    );
    assert!(matches!(
        client.poll_typed_device_link(&mut receiver).await.unwrap(),
        DeviceLinkPoll::Approved(_)
    ));
    assert!(matches!(
        client.poll_typed_device_link(&mut receiver).await,
        Err(DeviceError::NotPending)
    ));
}

#[tokio::test]
async fn device_link_result_shape_must_match_the_selected_path() {
    let (qr_client, qr_transport, mut qr_pending, _) = started_link().await;
    qr_transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "status": "approved",
            "nonce": STANDARD.encode([0u8; 12]),
            "ciphertext": STANDARD.encode([0u8; 48]),
        }))
        .unwrap(),
    );
    assert!(matches!(
        qr_client.poll_device_link(&mut qr_pending).await,
        Err(DeviceError::MalformedAnswer)
    ));
    assert!(matches!(
        qr_client.poll_device_link(&mut qr_pending).await,
        Err(DeviceError::NotPending)
    ));

    let (typed_client, typed_transport, typed_link, public_key) = started_link().await;
    let id = typed_link.id().to_owned();
    let code = typed_link.typed_code().unwrap().to_owned();
    let session_id = STANDARD.encode(typed_link.qr().unwrap().session_id());
    let (new_device, _) = typed_link.begin_typed_path().unwrap();
    typed_transport.push_json(200, pending_link_detail(&id, &session_id, &public_key));
    let (_approver, approver_message) = typed_client.begin_typed_device_approval(&id, &code).await.unwrap();
    let mut typed_pending = new_device.finish(&approver_message).unwrap();
    typed_transport.push_json(
        200,
        serde_json::to_vec(&serde_json::json!({
            "status": "approved",
            "approver_public": STANDARD.encode([0u8; 32]),
            "nonce": STANDARD.encode([0u8; 12]),
            "ciphertext": STANDARD.encode([0u8; 48]),
        }))
        .unwrap(),
    );
    assert!(matches!(
        typed_client.poll_typed_device_link(&mut typed_pending).await,
        Err(DeviceError::MalformedAnswer)
    ));
    assert!(matches!(
        typed_client.poll_typed_device_link(&mut typed_pending).await,
        Err(DeviceError::NotPending)
    ));
}

async fn started_link() -> (
    Client,
    Arc<ScriptedTransport>,
    crate::devices::PendingNewDeviceLink,
    [u8; 32],
) {
    let transport = Arc::new(ScriptedTransport::json(
        200,
        br#"{"expires_at":"2099-01-01T00:00:00Z"}"#.to_vec(),
    ));
    let client = Client::new(ClientConfig::for_tests(), transport.clone()).unwrap();
    client.set_authentication("token", "account").unwrap();
    client
        .set_session_key_for_test(Arc::new(MasterKey::from_bytes([7; 32])))
        .unwrap();
    let pending = client.start_device_link("reported device".into()).await.unwrap();
    let request = transport.requests().pop().unwrap();
    let value: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    let session_id = STANDARD.decode(value["session_id"].as_str().unwrap()).unwrap();
    assert_eq!(session_id.len(), 16);
    let public = STANDARD.decode(value["public_key"].as_str().unwrap()).unwrap();
    (client, transport, pending, public.try_into().unwrap())
}

fn pending_link_detail(id: &str, session_id: &str, public_key: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": id,
        "session_id": session_id,
        "public_key": STANDARD.encode(public_key),
        "device_name": "reported device",
        "reported_by_device": true,
        "status": "pending",
        "expires_at": "2099-01-01T00:00:00Z",
    }))
    .unwrap()
}

fn approved_result(sealed: &beebeeb_core::device_link::SealedAccountKeyMaterial) -> Vec<u8> {
    format!(
        r#"{{"status":"approved","approver_public":"{}","nonce":"{}","ciphertext":"{}"}}"#,
        STANDARD.encode(sealed.approver_public()),
        STANDARD.encode(sealed.nonce()),
        STANDARD.encode(sealed.ciphertext())
    )
    .into_bytes()
}
