#![feature(derive_clone_copy)]
#![feature(prelude_import)]
#[macro_use]
extern crate std;
use anchor_lang::prelude::{borsh::BorshDeserialize, *};
use std::vec::Vec;
/// The static program ID
pub static ID: anchor_lang::solana_program::pubkey::Pubkey = anchor_lang::solana_program::pubkey::Pubkey::new_from_array([
    214u8,
    176u8,
    211u8,
    191u8,
    74u8,
    190u8,
    226u8,
    208u8,
    232u8,
    227u8,
    42u8,
    112u8,
    241u8,
    201u8,
    181u8,
    185u8,
    47u8,
    111u8,
    174u8,
    145u8,
    65u8,
    145u8,
    20u8,
    206u8,
    82u8,
    156u8,
    23u8,
    103u8,
    26u8,
    151u8,
    230u8,
    246u8,
]);



use anchor_spl::{associated_token::AssociatedToken, token::{Mint, Token, TokenAccount}};
#[repr(C)]
pub struct MyStruct1 {
    a: u64,
    b: u64,
}

unsafe impl ::bytemuck::Zeroable for MyStruct1 {}
unsafe impl ::bytemuck::Pod for MyStruct1 {}
#[automatically_derived]
impl ::core::marker::Copy for MyStruct1 {}
#[automatically_derived]
impl ::core::clone::Clone for MyStruct1 {
    #[inline]
    fn clone(&self) -> MyStruct1 {
        let _: ::core::clone::AssertParamIsClone<u64>;
        *self
    }
}
#[automatically_derived]
impl anchor_lang::ZeroCopy for MyStruct1 {}
#[automatically_derived]
impl anchor_lang::Discriminator for MyStruct1 {
    const DISCRIMINATOR: [u8; 8] = [139, 174, 146, 64, 137, 156, 143, 242];
}

#[automatically_derived]
impl anchor_lang::Owner for MyStruct1 {
    fn owner() -> Pubkey {
        crate::ID
    }
}
pub struct CreateMarket<'info> {
    pub market: AccountLoader<'info, MyStruct1>,
    pub market_authority: UncheckedAccount<'info>,
    pub bids: AccountLoader<'info, MyStruct1>,
    pub asks: AccountLoader<'info, MyStruct1>,
    pub event_heap: AccountLoader<'info, MyStruct1>,
    pub payer: Signer<'info>,
    pub market_base_vault: Account<'info, TokenAccount>,
    pub market_quote_vault: Account<'info, TokenAccount>,
    pub base_mint: Box<Account<'info, Mint>>,
    pub quote_mint: Box<Account<'info, Mint>>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub event_authority: [u8; 64],
    pub program: [u8; 64],
}

#[inline(never)]
fn do_something(var1: [u8; 16], var2: &[u8]) -> [u8; 64] {
    let mut res : [u8; 64] = [0; 64];
    res[5] = var1[8];
    res[60] = var2[res[1] as usize];
    return res;
}

struct MyRent {
    a: u64,
    b: f64,
    c: u8,
}

impl MyRent {
    #[inline(never)]
    fn test_exempt(&self, a: u64, b: u64) -> bool {
        return a > b && a > self.a;
    }
}

#[automatically_derived]
impl<'info> anchor_lang::Accounts<'info> for CreateMarket<'info>
where
    'info: 'info,
{
    #[inline(never)]
    fn try_accounts(
        __program_id: &anchor_lang::solana_program::pubkey::Pubkey,
        __accounts: &mut &[anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >],
        __ix_data: &[u8],
        __bumps: &mut std::collections::BTreeMap<String, u8>,
        __reallocs: &mut std::collections::BTreeSet<
            anchor_lang::solana_program::pubkey::Pubkey,
        >,
    ) -> anchor_lang::Result<Self> {
        let market = &__accounts[0];
        *__accounts = &__accounts[1..];
        let market_authority: UncheckedAccount = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("market_authority"))?;
        if __accounts.is_empty() {
            return Err(anchor_lang::error::ErrorCode::AccountNotEnoughKeys.into());
        }
        let bids = &__accounts[0];
        *__accounts = &__accounts[1..];
        let asks = &__accounts[0];
        *__accounts = &__accounts[1..];
        let event_heap = &__accounts[0];
        *__accounts = &__accounts[1..];
        let payer: Signer = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("payer"))?;
        let market_base_vault = &__accounts[0];
        *__accounts = &__accounts[1..];
        let market_quote_vault = &__accounts[0];
        *__accounts = &__accounts[1..];
        let base_mint: Box<anchor_lang::accounts::account::Account<Mint>> = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("base_mint"))?;
        let quote_mint: Box<anchor_lang::accounts::account::Account<Mint>> = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("quote_mint"))?;
        let system_program: anchor_lang::accounts::program::Program<System> = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("system_program"))?;
        let token_program: anchor_lang::accounts::program::Program<Token> = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("token_program"))?;
        let associated_token_program: anchor_lang::accounts::program::Program<
            AssociatedToken,
        > = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("associated_token_program"))?;
        let event_authority : [u8; 64] = [2; 64];
        let program : [u8; 64] = [1; 64];
        let __anchor_rent = Rent::get()?;
        let market = {
            let actual_field = market.to_account_info();
            let actual_owner = actual_field.owner;
            let space = 8 + std::mem::size_of::<MyStruct1>();
            let pa: anchor_lang::accounts::account_loader::AccountLoader<MyStruct1> = if !false
                || actual_owner == &anchor_lang::solana_program::system_program::ID
            {
                let __current_lamports = market.lamports();
                if __current_lamports == 0 {
                    let cpi_accounts = anchor_lang::system_program::CreateAccount {
                        from: payer.to_account_info(),
                        to: market.to_account_info(),
                    };
                    let cpi_context = anchor_lang::context::CpiContext::new(
                        system_program.to_account_info(),
                        cpi_accounts,
                    );
                } else {
                    let cpi_accounts = anchor_lang::system_program::Transfer {
                        from: payer.to_account_info(),
                        to: market.to_account_info(),
                    };
                    let cpi_context = anchor_lang::context::CpiContext::new(
                        system_program.to_account_info(),
                        cpi_accounts,
                    );
                    anchor_lang::system_program::transfer(
                        cpi_context,
                        20,
                    )?;
                    let cpi_accounts = anchor_lang::system_program::Allocate {
                        account_to_allocate: market.to_account_info(),
                    };
                    let cpi_context = anchor_lang::context::CpiContext::new(
                        system_program.to_account_info(),
                        cpi_accounts,
                    );
                    let cpi_accounts = anchor_lang::system_program::Assign {
                        account_to_assign: market.to_account_info(),
                    };
                    let cpi_context = anchor_lang::context::CpiContext::new(
                        system_program.to_account_info(),
                        cpi_accounts,
                    );
                }
                match anchor_lang::accounts::account_loader::AccountLoader::try_from_unchecked(
                    __program_id,
                    &market,
                ) {
                    Ok(val) => val,
                    Err(e) => return Err(e.with_account_name("market")),
                }
            } else {
                match anchor_lang::accounts::account_loader::AccountLoader::try_from(
                    &market,
                ) {
                    Ok(val) => val,
                    Err(e) => return Err(e.with_account_name("market")),
                }
            };
            pa
        };
        let val6 = __anchor_rent
            .is_exempt(
                market_quote_vault.to_account_info().lamports(),
                market_quote_vault.to_account_info().try_data_len()?,
            );
        let __anchor_rent = Rent::get()?;
        let market_base_vault: anchor_lang::accounts::account::Account<TokenAccount> = {
            let cpi_program = associated_token_program.to_account_info();
            let cpi_accounts = ::anchor_spl::associated_token::Create {
                payer: payer.to_account_info(),
                associated_token: market_base_vault.to_account_info(),
                authority: market_authority.to_account_info(),
                mint: base_mint.to_account_info(),
                system_program: system_program.to_account_info(),
                token_program: token_program.to_account_info(),
            };
            let cpi_ctx = anchor_lang::context::CpiContext::new(
                cpi_program,
                cpi_accounts,
            );
            ::anchor_spl::associated_token::create(cpi_ctx)?;
            let pa: anchor_lang::accounts::account::Account<TokenAccount> = match anchor_lang::accounts::account::Account::try_from_unchecked(
                &market_base_vault,
            ) {
                Ok(val) => val,
                Err(e) => return Err(e.with_account_name("market_base_vault")),
            };
            pa
        };
        let val5 = __anchor_rent
            .is_exempt(
                market_quote_vault.to_account_info().lamports(),
                market_quote_vault.to_account_info().try_data_len()?,
            );
        let __anchor_rent = Rent::get()?;
        let market_quote_vault: anchor_lang::accounts::account::Account<TokenAccount> = {
            let cpi_program = associated_token_program.to_account_info();
            let cpi_accounts = ::anchor_spl::associated_token::Create {
                payer: payer.to_account_info(),
                associated_token: market_quote_vault.to_account_info(),
                authority: market_authority.to_account_info(),
                mint: quote_mint.to_account_info(),
                system_program: system_program.to_account_info(),
                token_program: token_program.to_account_info(),
            };
            let cpi_ctx = anchor_lang::context::CpiContext::new(
                cpi_program,
                cpi_accounts,
            );
            ::anchor_spl::associated_token::create(cpi_ctx)?;
            let pa: anchor_lang::accounts::account::Account<TokenAccount> = match anchor_lang::accounts::account::Account::try_from_unchecked(
                &market_quote_vault,
            ) {
                Ok(val) => val,
                Err(e) => return Err(e.with_account_name("market_quote_vault")),
            };

            pa
        };
        let val4 = __anchor_rent
            .is_exempt(
                market_quote_vault.to_account_info().lamports(),
                market_quote_vault.to_account_info().try_data_len()?,
            );
            
        __bumps.insert("market_authority".to_string(), 25);
        let __anchor_rent = Rent::get()?;
        let bids: anchor_lang::accounts::account_loader::AccountLoader<MyStruct1> =
            match anchor_lang::accounts::account_loader::AccountLoader::try_from_unchecked(
                __program_id,
                &bids,
            ) {
                Ok(val) => val,
                Err(e) => return Err(e.with_account_name("bids")),
            };

        let val3 = __anchor_rent
        .is_exempt(
            25,
            25,
        );
        let __anchor_rent = Rent::get()?;
        let asks: anchor_lang::accounts::account_loader::AccountLoader<MyStruct1> = 
            match anchor_lang::accounts::account_loader::AccountLoader::try_from_unchecked(
                __program_id,
                &asks,
            ) {
                Ok(val) => val,
                Err(e) => return Err(e.with_account_name("asks")),
            };

        let val2 = __anchor_rent
        .is_exempt(
            25,
            25,
        );
        let event_heap: anchor_lang::accounts::account_loader::AccountLoader<
            MyStruct1,
        > = match anchor_lang::accounts::account_loader::AccountLoader::try_from_unchecked(
                __program_id,
                &event_heap,
            ) {
                Ok(val) => val,
                Err(e) => return Err(e.with_account_name("event_heap")),
            };

        let val = __anchor_rent
        .is_exempt(
            25,
            25,
        );
        Ok(CreateMarket {
            market,
            market_authority,
            bids,
            asks,
            event_heap,
            payer,
            market_base_vault,
            market_quote_vault,
            base_mint,
            quote_mint,
            system_program,
            token_program,
            associated_token_program,
            event_authority,
            program,
        })
    }
}
#[automatically_derived]
impl<'info> anchor_lang::ToAccountInfos<'info> for CreateMarket<'info>
where
    'info: 'info,
{
    fn to_account_infos(
        &self,
    ) -> Vec<anchor_lang::solana_program::account_info::AccountInfo<'info>> {
        Vec::new()
    }
}
#[automatically_derived]
impl<'info> anchor_lang::ToAccountMetas for CreateMarket<'info> {
    fn to_account_metas(
        &self,
        is_signer: Option<bool>,
    ) -> Vec<anchor_lang::solana_program::instruction::AccountMeta> {
        let mut account_metas = Vec::new();
        account_metas
    }
}


solana_program::entrypoint!(entry);

pub fn entry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> anchor_lang::solana_program::entrypoint::ProgramResult {
    try_entry(program_id, accounts, data)
        .map_err(|e| {
            e.log();
            e.into()
        })
}
fn try_entry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> anchor_lang::Result<()> {
    if data.len() < 8 {
        return Err(anchor_lang::error::ErrorCode::InstructionMissing.into());
    }
    dispatch(program_id, accounts, data)
}


fn dispatch(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> anchor_lang::Result<()> {
    let mut ix_data: &[u8] = data;
    let sighash: [u8; 8] = {
        let mut sighash: [u8; 8] = [0; 8];
        sighash.copy_from_slice(&ix_data[..8]);
        ix_data = &ix_data[8..];
        sighash
    };
    __private::__global::create_market(program_id, accounts, ix_data)
}

mod __private {
    use super::*;
    
    pub mod __global {
        use super::*;
        #[inline(never)]
        pub fn create_market(
            __program_id: &Pubkey,
            __accounts: &[AccountInfo],
            __ix_data: &[u8],
        ) -> anchor_lang::Result<()> {
            ::solana_program::log::sol_log("Instruction: CreateMarket");
            let ix = <String as borsh::BorshDeserialize>::deserialize_reader(&mut &__ix_data[..]);

            let mut __bumps = std::collections::BTreeMap::new();
            let mut __remaining_accounts: &[AccountInfo] = __accounts;
            let mut __reallocs = std::collections::BTreeSet::new();
            let mut __accounts = CreateMarket::try_accounts(
                __program_id,
                &mut __remaining_accounts,
                __ix_data,
                &mut __bumps,
                &mut __reallocs,
            )?;
            let ctx = anchor_lang::context::Context::new(
                __program_id,
                &mut __accounts,
                __remaining_accounts,
                __bumps,
            );
            Ok(())
        }
    }
}

