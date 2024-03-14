//! A central-limit order book (CLOB) program that targets the Sealevel runtime.

use anchor_lang::prelude::{
    borsh::{BorshDeserialize},
    *,
};
use crate::error::OpenBookError;
use crate::pubkey_option::NonZeroKey;

declare_id!("9QJrVWzEaZBjao31iqBNaGqmXUNim7tmdb9kgczqGQXD");


pub mod accounts_ix;
pub mod accounts_zerocopy;
pub mod error;
pub mod logs;
pub mod pubkey_option;
pub mod state;


use accounts_ix::*;
use state::{OracleConfigParams};

#[program]
pub mod openbook_v2 {
    use super::*;

    /// Create a [`Market`](crate::state::Market) for a given token pair.
    #[allow(clippy::too_many_arguments)]
    pub fn create_market(
        ctx: Context<CreateMarket>,
        _name: String,
        _oracle_config: OracleConfigParams,
        _quote_lot_size: i64,
        _base_lot_size: i64,
        _maker_fee: i64,
        _taker_fee: i64,
        _time_expiry: i64,
    ) -> Result<()> {
        msg!("Starting");
        let oracle_a = ctx.accounts.oracle_a.non_zero_key();
        let oracle_b = ctx.accounts.oracle_b.non_zero_key();
    
        msg!("Ora: {}, Orb: {}", oracle_a.is_some(), oracle_b.is_some());
        if oracle_b.is_some() {
            msg!("Inside Err branch");
            return Err(OpenBookError::InvalidSecondOracle.into());
        }
    
        msg!("Before open market");
        Ok(())
    }
}