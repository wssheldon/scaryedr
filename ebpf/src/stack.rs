// src/stack.rs
#![allow(incomplete_features)]

/// Maximum stack size allowed in BPF programs
pub const BPF_STACK_LIMIT: usize = 512;

/// Trait for compile-time stack size validation
pub trait ValidateStackSize<const N: usize> {
    const VALID: bool = N <= BPF_STACK_LIMIT;
    const SIZE: usize = N;
    const ASSERT: () = assert!(
        Self::VALID,
        concat!(
            "BPF stack size exceeded: struct size is ",
            stringify!(N),
            " bytes, but maximum allowed is ",
            stringify!(BPF_STACK_LIMIT),
            " bytes"
        )
    );
}

/// Validates stack size at compile time
#[allow(dead_code)]
pub const fn validate_stack_size<const N: usize>() -> bool {
    assert!(N <= BPF_STACK_LIMIT, "BPF stack size exceeded");
    true
}

#[macro_export]
macro_rules! stack_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident: $ty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[repr(C)]
        // Add allow(dead_code) to the struct itself
        #[allow(dead_code)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $ty
            ),*
        }

        impl $name {
            /// Total size of the struct in bytes
            #[allow(dead_code)]
            const STACK_SIZE: usize = 0 $(+ core::mem::size_of::<$ty>())*;

            /// Validates that the struct fits within BPF stack limits
            #[allow(dead_code)]
            const fn validate_stack() -> bool {
                $crate::stack::validate_stack_size::<{ Self::STACK_SIZE }>()
            }

            /// Get the current stack usage in bytes
            #[allow(dead_code)]
            pub const fn stack_size() -> usize {
                Self::STACK_SIZE
            }
        }

        // Implement validation trait
        impl $crate::stack::ValidateStackSize<{ $name::STACK_SIZE }> for $name {}

        // Static assertion with const-friendly error
        #[allow(dead_code)]
        const _: () = assert!(
            $name::STACK_SIZE <= $crate::stack::BPF_STACK_LIMIT,
            concat!(
                "\nError: Struct '",
                stringify!($name),
                "' exceeds BPF stack size limit of 512 bytes\n",
                "Current size: ",
                stringify!($name::STACK_SIZE),
                " bytes"
            )
        );
    };
}

pub use stack_struct;
