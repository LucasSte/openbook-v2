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
    pub event_authority: AccountInfo<'info>,
    pub program: AccountInfo<'info>,
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
        if __accounts.is_empty() {
            return Err(anchor_lang::error::ErrorCode::AccountNotEnoughKeys.into());
        }
        let asks = &__accounts[0];
        *__accounts = &__accounts[1..];
        if __accounts.is_empty() {
            return Err(anchor_lang::error::ErrorCode::AccountNotEnoughKeys.into());
        }
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
        if __accounts.is_empty() {
            return Err(anchor_lang::error::ErrorCode::AccountNotEnoughKeys.into());
        }
        let market_base_vault = &__accounts[0];
        *__accounts = &__accounts[1..];
        if __accounts.is_empty() {
            return Err(anchor_lang::error::ErrorCode::AccountNotEnoughKeys.into());
        }
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
        let event_authority: AccountInfo = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("event_authority"))?;
        let program: AccountInfo = anchor_lang::Accounts::try_accounts(
                __program_id,
                __accounts,
                __ix_data,
                __bumps,
                __reallocs,
            )
            .map_err(|e| e.with_account_name("program"))?;
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
        let __anchor_rent = Rent::get()?;
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
        let mut account_infos = Vec::new();
        account_infos.extend(self.market.to_account_infos());
        account_infos.extend(self.market_authority.to_account_infos());
        account_infos.extend(self.bids.to_account_infos());
        account_infos.extend(self.asks.to_account_infos());
        account_infos.extend(self.event_heap.to_account_infos());
        account_infos.extend(self.payer.to_account_infos());
        account_infos.extend(self.market_base_vault.to_account_infos());
        account_infos.extend(self.market_quote_vault.to_account_infos());
        account_infos.extend(self.base_mint.to_account_infos());
        account_infos.extend(self.quote_mint.to_account_infos());
        account_infos.extend(self.system_program.to_account_infos());
        account_infos.extend(self.token_program.to_account_infos());
        account_infos.extend(self.associated_token_program.to_account_infos());
        account_infos.extend(self.event_authority.to_account_infos());
        account_infos.extend(self.program.to_account_infos());
        account_infos
    }
}
#[automatically_derived]
impl<'info> anchor_lang::ToAccountMetas for CreateMarket<'info> {
    fn to_account_metas(
        &self,
        is_signer: Option<bool>,
    ) -> Vec<anchor_lang::solana_program::instruction::AccountMeta> {
        let mut account_metas = Vec::new();
        account_metas.extend(self.market.to_account_metas(Some(true)));
        account_metas.extend(self.market_authority.to_account_metas(None));
        account_metas.extend(self.bids.to_account_metas(None));
        account_metas.extend(self.asks.to_account_metas(None));
        account_metas.extend(self.event_heap.to_account_metas(None));
        account_metas.extend(self.payer.to_account_metas(None));
        account_metas.extend(self.market_base_vault.to_account_metas(None));
        account_metas.extend(self.market_quote_vault.to_account_metas(None));
        account_metas.extend(self.base_mint.to_account_metas(None));
        account_metas.extend(self.quote_mint.to_account_metas(None));
        account_metas.extend(self.system_program.to_account_metas(None));
        account_metas.extend(self.token_program.to_account_metas(None));
        account_metas.extend(self.associated_token_program.to_account_metas(None));
        account_metas.extend(self.event_authority.to_account_metas(None));
        account_metas.extend(self.program.to_account_metas(None));
        account_metas
    }
}


pub(crate) mod __client_accounts_create_market {
    use super::*;
    use anchor_lang::prelude::borsh;
    /// Generated client accounts for [`CreateMarket`].
    pub struct CreateMarket {
        pub market: anchor_lang::solana_program::pubkey::Pubkey,
        pub market_authority: anchor_lang::solana_program::pubkey::Pubkey,
        pub bids: anchor_lang::solana_program::pubkey::Pubkey,
        pub asks: anchor_lang::solana_program::pubkey::Pubkey,
        pub event_heap: anchor_lang::solana_program::pubkey::Pubkey,
        pub payer: anchor_lang::solana_program::pubkey::Pubkey,
        pub market_base_vault: anchor_lang::solana_program::pubkey::Pubkey,
        pub market_quote_vault: anchor_lang::solana_program::pubkey::Pubkey,
        pub base_mint: anchor_lang::solana_program::pubkey::Pubkey,
        pub quote_mint: anchor_lang::solana_program::pubkey::Pubkey,
        pub system_program: anchor_lang::solana_program::pubkey::Pubkey,
        pub token_program: anchor_lang::solana_program::pubkey::Pubkey,
        pub associated_token_program: anchor_lang::solana_program::pubkey::Pubkey,
        pub event_authority: anchor_lang::solana_program::pubkey::Pubkey,
        pub program: anchor_lang::solana_program::pubkey::Pubkey,
    }

    #[automatically_derived]
    impl anchor_lang::ToAccountMetas for CreateMarket {
        fn to_account_metas(
            &self,
            is_signer: Option<bool>,
        ) -> Vec<anchor_lang::solana_program::instruction::AccountMeta> {
            let mut account_metas = Vec::new();
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.market,
                        true,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.market_authority,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.bids,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.asks,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.event_heap,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.payer,
                        true,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.market_base_vault,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        self.market_quote_vault,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.base_mint,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.quote_mint,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.system_program,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.token_program,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.associated_token_program,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.event_authority,
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        self.program,
                        false,
                    ),
                );
            account_metas
        }
    }
}


pub(crate) mod __cpi_client_accounts_create_market {
    use super::*;
    /// Generated CPI struct of the accounts for [`CreateMarket`].
    pub struct CreateMarket<'info> {
        pub market: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub market_authority: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        ///Accounts are initialized by client,
        ///anchor discriminator is set first when ix exits,
        pub bids: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub asks: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub event_heap: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub payer: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub market_base_vault: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        pub market_quote_vault: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        pub base_mint: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub quote_mint: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub system_program: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        pub token_program: anchor_lang::solana_program::account_info::AccountInfo<'info>,
        pub associated_token_program: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        pub event_authority: anchor_lang::solana_program::account_info::AccountInfo<
            'info,
        >,
        pub program: anchor_lang::solana_program::account_info::AccountInfo<'info>,
    }
    #[automatically_derived]
    impl<'info> anchor_lang::ToAccountMetas for CreateMarket<'info> {
        fn to_account_metas(
            &self,
            is_signer: Option<bool>,
        ) -> Vec<anchor_lang::solana_program::instruction::AccountMeta> {
            let mut account_metas = Vec::new();
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.market),
                        true,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.market_authority),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.bids),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.asks),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.event_heap),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.payer),
                        true,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.market_base_vault),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        anchor_lang::Key::key(&self.market_quote_vault),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.base_mint),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.quote_mint),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.system_program),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.token_program),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.associated_token_program),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.event_authority),
                        false,
                    ),
                );
            account_metas
                .push(
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        anchor_lang::Key::key(&self.program),
                        false,
                    ),
                );
            account_metas
        }
    }
    #[automatically_derived]
    impl<'info> anchor_lang::ToAccountInfos<'info> for CreateMarket<'info> {
        fn to_account_infos(
            &self,
        ) -> Vec<anchor_lang::solana_program::account_info::AccountInfo<'info>> {
            let mut account_infos = Vec::new();
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.market));
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(&self.market_authority),
                );
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.bids));
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.asks));
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.event_heap));
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.payer));
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(
                        &self.market_base_vault,
                    ),
                );
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(
                        &self.market_quote_vault,
                    ),
                );
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.base_mint));
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.quote_mint));
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(&self.system_program),
                );
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(&self.token_program),
                );
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(
                        &self.associated_token_program,
                    ),
                );
            account_infos
                .extend(
                    anchor_lang::ToAccountInfos::to_account_infos(&self.event_authority),
                );
            account_infos
                .extend(anchor_lang::ToAccountInfos::to_account_infos(&self.program));
            account_infos
        }
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

