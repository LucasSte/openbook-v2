//! A central-limit order book (CLOB) program that targets the Sealevel runtime.

use anchor_lang::prelude::{
    borsh::{BorshDeserialize},
    *,
};

declare_id!("Fd8e5ytFgUtiWHDsD59sQaydRY4Dp9xKK6BFAdkE2WC5");




#[derive(AnchorDeserialize, AnchorSerialize, Debug, Clone)]
pub struct OracleConfigParams {
    pub conf_filter: f32,
    pub max_staleness_slots: Option<u32>,
}

use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
};

#[account(zero_copy)]
pub struct MyStruct1 {
    a: u64,
    b: u64,
}

#[event_cpi]
#[derive(Accounts)]
pub struct CreateMarket<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<MyStruct1>(),
    )]
    pub market: AccountLoader<'info, MyStruct1>,
    #[account(
        seeds = [b"Market".as_ref(), market.key().to_bytes().as_ref()],
        bump,
    )]
    /// CHECK:
    pub market_authority: UncheckedAccount<'info>,

    /// Accounts are initialized by client,
    /// anchor discriminator is set first when ix exits,
    #[account(zero)]
    pub bids: AccountLoader<'info, MyStruct1>,
    #[account(zero)]
    pub asks: AccountLoader<'info, MyStruct1>,
    #[account(zero)]
    pub event_heap: AccountLoader<'info, MyStruct1>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        associated_token::mint = base_mint,
        associated_token::authority = market_authority,
    )]
    pub market_base_vault: Account<'info, TokenAccount>,
    #[account(
        init,
        payer = payer,
        associated_token::mint = quote_mint,
        associated_token::authority = market_authority,
    )]
    pub market_quote_vault: Account<'info, TokenAccount>,

    pub base_mint: Box<Account<'info, Mint>>,
    pub quote_mint: Box<Account<'info, Mint>>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    /// CHECK: The oracle can be one of several different account types
    pub oracle_a: Option<UncheckedAccount<'info>>,
    /// CHECK: The oracle can be one of several different account types
    pub oracle_b: Option<UncheckedAccount<'info>>,

}


#[program]
pub mod openbook_v2 {
    use super::*;

    /// Create a [`Market`](crate::state::Market) for a given token pair.
    #[allow(clippy::too_many_arguments)]
    pub fn create_market(
        _ctx: Context<CreateMarket>,
        _name: String,
        _oracle_config: OracleConfigParams,
        _quote_lot_size: i64,
        _base_lot_size: i64,
        _maker_fee: i64,
        _taker_fee: i64,
        _time_expiry: i64,
    ) -> Result<()> {
        msg!("Starting");

        // let oracle_a = ctx.accounts.oracle_a.non_zero_key();
        // let oracle_b = ctx.accounts.oracle_b.non_zero_key();
    
        // // true, false
        // msg!("Ora: {}, Orb: {}", oracle_a.is_some(), oracle_b.is_some());
        // if oracle_b.is_some() {
        //     msg!("Inside Err branch");
        //     return Err(OpenBookError::InvalidSecondOracle.into());
        // }
    
        msg!("Before open market");
        Ok(())
    }
}
