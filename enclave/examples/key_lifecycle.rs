//! Example: NIST SP 800-57 Key Lifecycle state transitions.

use traces_sm_enclave::nist::{KeyLifecycleState, KeyUsage};

fn main() {
    println!("=== traces-sm Key Lifecycle Example ===");

    let mut state = KeyLifecycleState::PreOperational;
    let usage = KeyUsage {
        sign: true,
        verify: true,
        ..Default::default()
    };

    println!("Initial State: {:?}", state);
    println!("KeyUsage Sign: {}, Verify: {}", usage.sign, usage.verify);

    // Transition PreOperational -> Operational
    state = KeyLifecycleState::Operational;
    println!("Active State: {:?}", state);
    assert!(state.can_encrypt());

    // Transition Operational -> Deactivated
    state = KeyLifecycleState::Deactivated;
    println!("Deactivated State: {:?}", state);
    assert!(!state.can_encrypt());
    assert!(state.can_decrypt_historical());

    println!("✓ Key Lifecycle state transition validation passed!");
}
