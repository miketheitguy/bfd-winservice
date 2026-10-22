//! Restrict only our own account; never grant a service SID or a privilege.
use super::*;
use crate::local_rpc::test_support::{restricted_token, OwnIdentity};

#[test]
fn native_write_restricted_caller_requires_its_group_in_both_lists() {
    for group in [WORLD, "S-1-5-11"] {
        let fixture = Fixture::start(&user(), group, 0, true);
        let token = restricted_token(WORLD, false);
        {
            let _identity = OwnIdentity::enter(&token);
            let result = call_with_policy(&fixture.endpoint, &user(), WORLD, 2, 2_000, None);
            if group == WORLD {
                assert_eq!(result.unwrap().status, 0);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            }
        }
        assert_eq!(fixture.calls(), if group == WORLD { "Start\n" } else { "" });
        fixture.stop();
    }
}

#[test]
fn native_deny_only_caller_group_is_rejected_before_dispatch() {
    let fixture = Fixture::start(&user(), WORLD, 0, true);
    let token = restricted_token(WORLD, true);
    {
        let _identity = OwnIdentity::enter(&token);
        assert!(fixture.call(2).is_err());
    }
    assert!(fixture.calls().is_empty());
    fixture.stop();
}
