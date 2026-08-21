use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};
use anchor_spl::associated_token::{self, AssociatedToken, Create};
use anchor_spl::token_interface::{
    self, CloseAccount, Mint, TokenAccount, TokenInterface, TransferChecked,
};

#[cfg(not(feature = "no-entrypoint"))]
macro_rules! security_txt {
    ($($name:ident: $value:expr),* $(,)?) => {
        #[cfg_attr(target_arch = "bpf", link_section = ".security.txt")]
        #[allow(dead_code)]
        #[no_mangle]
        pub static security_txt: &str = concat! {
            "=======BEGIN SECURITY.TXT V1=======\0",
            $(stringify!($name), "\0", $value, "\0",)*
            "=======END SECURITY.TXT V1=======\0"
        };
    };
}

// SolPG / Cargo dependency required for security.txt metadata:
// solana-security-txt = "1.1.1"
//
// SolPG deploy steps:
// 1) Paste this file into SolPG's lib.rs.
// 2) Replace declare_id!(.EjKyCEqT3GkDP6PJajYqjrsWQNosfYFWZE2US2rWp7bR..) with SolPG's generated Program ID before final build/deploy.
// 3) Deploy, then make the program immutable by removing upgrade authority:
//    solana program set-upgrade-authority <PROGRAM_ID> --final

declare_id!("EjKyCEqT3GkDP6PJajYqjrsWQNosfYFWZE2US2rWp7bR");

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "CoinRobot Vault for dex trading",
    source_release: "v1.7",
    project_url: "https://x.coinrobot.ai",
    contacts: "email:security@coinrobot.ai",
    policy: "https://x.coinrobot.ai/security",
    preferred_languages: "en",
    acknowledgements: "CoinRobot community trading bot Vault for Solana DEX trading. The program lets Vault owners custody trading capital in PDA-owned token accounts for automated DEX execution and owner-controlled withdrawals."
}

pub const MAX_ALLOWED_MINTS: usize = 64;
pub const MAX_JUPITER_IX_DATA_BYTES: usize = 128;

#[program]
pub mod solana_trading_vault {
    use super::*;

    pub fn initialize_vault<'info>(
        ctx: Context<'_, '_, 'info, 'info, InitializeVault<'info>>,
        bot_address: Pubkey,
        jupiter_router: Pubkey,
        initial_mints: Vec<Pubkey>,
    ) -> Result<()> {
        require!(bot_address != Pubkey::default(), VaultError::InvalidInput);
        require!(
            jupiter_router != Pubkey::default(),
            VaultError::InvalidRouter
        );
        require!(
            initial_mints.len() <= MAX_ALLOWED_MINTS,
            VaultError::TooManyTokens
        );

        let mut normalized_mints = Vec::new();
        for mint in initial_mints {
            if mint != Pubkey::default() && !normalized_mints.contains(&mint) {
                normalized_mints.push(mint);
            }
        }

        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.bot_address = bot_address;
        vault.jupiter_router = jupiter_router;
        vault.authority_bump = ctx.bumps.vault_authority;
        vault.allowed_mints = normalized_mints.clone();

        for mint in normalized_mints.iter() {
            emit!(TokenStatusUpdated {
                mint: *mint,
                allowed: true
            });
        }

        emit!(BotAddressUpdated {
            old_bot: Pubkey::default(),
            new_bot: bot_address,
        });
        emit!(RouterUpdated { jupiter_router });
        ensure_vault_atas(
            ctx.remaining_accounts,
            &ctx.accounts.owner.to_account_info(),
            &ctx.accounts.vault_authority.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            &ctx.accounts.associated_token_program.to_account_info(),
            &normalized_mints,
        )?;
        Ok(())
    }

    pub fn get_allowed_tokens(ctx: Context<ReadVault>) -> Result<Vec<Pubkey>> {
        Ok(ctx.accounts.vault.allowed_mints.clone())
    }

    pub fn is_allowed_token(ctx: Context<ReadVault>, mint: Pubkey) -> Result<bool> {
        Ok(ctx.accounts.vault.allowed_mints.contains(&mint))
    }

    pub fn allowed_tokens_length(ctx: Context<ReadVault>) -> Result<u32> {
        Ok(ctx.accounts.vault.allowed_mints.len() as u32)
    }

    pub fn add_token<'info>(
        ctx: Context<'_, '_, 'info, 'info, AddToken<'info>>,
        mint: Pubkey,
    ) -> Result<()> {
        require!(mint != Pubkey::default(), VaultError::InvalidToken);
        let vault = &mut ctx.accounts.vault;
        require!(
            !vault.allowed_mints.contains(&mint),
            VaultError::TokenAlreadyAllowed
        );
        require!(
            vault.allowed_mints.len() < MAX_ALLOWED_MINTS,
            VaultError::TooManyTokens
        );

        vault.allowed_mints.push(mint);
        emit!(TokenStatusUpdated {
            mint,
            allowed: true
        });
        ensure_vault_atas(
            ctx.remaining_accounts,
            &ctx.accounts.owner.to_account_info(),
            &ctx.accounts.vault_authority.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            &ctx.accounts.associated_token_program.to_account_info(),
            &[mint],
        )?;
        Ok(())
    }

    pub fn remove_token(ctx: Context<RemoveToken>, mint: Pubkey) -> Result<()> {
        require!(mint != Pubkey::default(), VaultError::InvalidToken);

        let vault_key = ctx.accounts.vault.key();
        let vault = &mut ctx.accounts.vault;
        let pos = vault
            .allowed_mints
            .iter()
            .position(|m| *m == mint)
            .ok_or(VaultError::TokenNotAllowed)?;

        require!(ctx.accounts.mint.key() == mint, VaultError::BadAccount);
        require!(
            ctx.accounts.vault_token_account.owner == ctx.accounts.vault_authority.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_account.mint == mint,
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_account.amount == 0,
            VaultError::TokenAccountNotEmpty
        );
        require!(
            ctx.accounts.vault_token_account.to_account_info().owner
                == &ctx.accounts.token_program.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.mint.to_account_info().owner == &ctx.accounts.token_program.key(),
            VaultError::BadAccount
        );
        let expected_ata = associated_token_address_with_program(
            &ctx.accounts.vault_authority.key(),
            &mint,
            &ctx.accounts.token_program.key(),
            &associated_token::ID,
        );
        require!(
            ctx.accounts.vault_token_account.key() == expected_ata,
            VaultError::BadAccount
        );

        let signer_seeds: &[&[u8]] = &[
            b"vault_authority",
            vault_key.as_ref(),
            &[vault.authority_bump],
        ];
        let cpi_accounts = CloseAccount {
            account: ctx.accounts.vault_token_account.to_account_info(),
            destination: ctx.accounts.owner.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token_interface::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            &[signer_seeds],
        ))?;
        emit!(TokenAccountClosed {
            token_account: ctx.accounts.vault_token_account.key(),
            mint,
            to: vault.owner,
        });

        vault.allowed_mints.swap_remove(pos);
        emit!(TokenStatusUpdated {
            mint,
            allowed: false
        });
        Ok(())
    }

    pub fn set_bot_address(ctx: Context<OwnerOnly>, new_bot: Pubkey) -> Result<()> {
        require!(new_bot != Pubkey::default(), VaultError::InvalidInput);
        let vault = &mut ctx.accounts.vault;
        let old_bot = vault.bot_address;
        vault.bot_address = new_bot;
        emit!(BotAddressUpdated { old_bot, new_bot });
        Ok(())
    }

    pub fn update_routers(ctx: Context<OwnerOnly>, new_jupiter_router: Pubkey) -> Result<()> {
        require!(
            new_jupiter_router != Pubkey::default(),
            VaultError::InvalidRouter
        );
        ctx.accounts.vault.jupiter_router = new_jupiter_router;
        emit!(RouterUpdated {
            jupiter_router: new_jupiter_router,
        });
        Ok(())
    }

    pub fn trade<'info>(
        ctx: Context<'_, '_, 'info, 'info, Trade<'info>>,
        token_in_mint: Pubkey,
        token_out_mint: Pubkey,
        amount_in: u64,
        min_amount_out: u64,
        jupiter_ix_data_len: u16,
        jupiter_ix_data: [u8; MAX_JUPITER_IX_DATA_BYTES],
    ) -> Result<()> {
        require!(
            (jupiter_ix_data_len as usize) <= MAX_JUPITER_IX_DATA_BYTES,
            VaultError::InvalidInput
        );
        let jupiter_ix_data = jupiter_ix_data[..jupiter_ix_data_len as usize].to_vec();
        let vault = &ctx.accounts.vault;
        require_bot_or_owner(vault, &ctx.accounts.caller.key())?;
        require!(
            amount_in > 0 && min_amount_out > 0,
            VaultError::InvalidInput
        );
        require!(token_in_mint != Pubkey::default(), VaultError::InvalidToken);
        require!(
            token_out_mint != Pubkey::default(),
            VaultError::InvalidToken
        );
        require!(token_in_mint != token_out_mint, VaultError::InvalidToken);
        require_allowed(vault, &token_in_mint)?;
        require_allowed(vault, &token_out_mint)?;
        require!(
            ctx.accounts.jupiter_program.key() == vault.jupiter_router,
            VaultError::InvalidRouter
        );

        require!(
            ctx.accounts.vault_token_in.owner == ctx.accounts.vault_authority.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_out.owner == ctx.accounts.vault_authority.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_in.mint == token_in_mint,
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_out.mint == token_out_mint,
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_in.to_account_info().owner
                == &ctx.accounts.token_program_in.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_out.to_account_info().owner
                == &ctx.accounts.token_program_out.key(),
            VaultError::BadAccount
        );
        require_vault_ata(
            &ctx.accounts.vault_authority.key(),
            &token_in_mint,
            &ctx.accounts.token_program_in.key(),
            &ctx.accounts.vault_token_in.key(),
        )?;
        require_vault_ata(
            &ctx.accounts.vault_authority.key(),
            &token_out_mint,
            &ctx.accounts.token_program_out.key(),
            &ctx.accounts.vault_token_out.key(),
        )?;

        let token_in_before = ctx.accounts.vault_token_in.amount;
        require!(
            token_in_before >= amount_in,
            VaultError::InsufficientBalance
        );
        let token_out_before = ctx.accounts.vault_token_out.amount;
        // Anchor named accounts are not included in ctx.remaining_accounts. The
        // client intentionally appends the same Jupiter program AccountInfo as the
        // final remaining account so invoke_signed can receive a complete
        // account_infos slice without allocating ctx.remaining_accounts.to_vec().
        let (jupiter_program_info, cpi_accounts) = ctx
            .remaining_accounts
            .split_last()
            .ok_or(VaultError::BadAccount)?;
        require!(
            jupiter_program_info.key() == ctx.accounts.jupiter_program.key(),
            VaultError::InvalidRouter
        );
        validate_trade_remaining_accounts(
            cpi_accounts,
            &ctx.accounts.vault_authority.key(),
            &ctx.accounts.vault_token_in.key(),
            &ctx.accounts.vault_token_out.key(),
            &ctx.accounts.token_program_in.key(),
            &ctx.accounts.token_program_out.key(),
        )?;

        let mut metas = Vec::with_capacity(cpi_accounts.len());
        for account in cpi_accounts.iter() {
            let is_signer = account.key() == ctx.accounts.vault_authority.key();
            if account.is_writable {
                metas.push(AccountMeta::new(account.key(), is_signer));
            } else {
                metas.push(AccountMeta::new_readonly(account.key(), is_signer));
            }
        }

        let vault_key = ctx.accounts.vault.key();
        let signer_seeds: &[&[u8]] = &[
            b"vault_authority",
            vault_key.as_ref(),
            &[vault.authority_bump],
        ];
        let ix = Instruction {
            program_id: ctx.accounts.jupiter_program.key(),
            accounts: metas,
            data: jupiter_ix_data,
        };
        invoke_signed(&ix, ctx.remaining_accounts, &[signer_seeds])?;

        ctx.accounts.vault_token_in.reload()?;
        ctx.accounts.vault_token_out.reload()?;

        let spent = token_in_before
            .checked_sub(ctx.accounts.vault_token_in.amount)
            .ok_or(VaultError::Math)?;
        let received = ctx
            .accounts
            .vault_token_out
            .amount
            .checked_sub(token_out_before)
            .ok_or(VaultError::Slippage)?;

        require!(spent <= amount_in, VaultError::InsufficientBalance);
        require!(received >= min_amount_out, VaultError::Slippage);

        emit!(TradeExecuted {
            token_in: token_in_mint,
            token_out: token_out_mint,
            router: ctx.accounts.jupiter_program.key(),
            amount_in,
            amount_spent: spent,
            amount_out: received,
        });
        Ok(())
    }

    pub fn withdraw_all<'info>(
        ctx: Context<'_, '_, 'info, 'info, WithdrawAll<'info>>,
    ) -> Result<()> {
        let vault = &ctx.accounts.vault;
        require_bot_or_owner(vault, &ctx.accounts.caller.key())?;
        require!(
            ctx.accounts.owner.key() == vault.owner,
            VaultError::Unauthorized
        );
        require!(
            ctx.remaining_accounts.len() % 3 == 0,
            VaultError::BadAccount
        );

        let vault_key = ctx.accounts.vault.key();
        let signer_seeds: &[&[u8]] = &[
            b"vault_authority",
            vault_key.as_ref(),
            &[vault.authority_bump],
        ];

        let mut i = 0;
        while i < ctx.remaining_accounts.len() {
            let vault_token_info = &ctx.remaining_accounts[i];
            let owner_token_info = &ctx.remaining_accounts[i + 1];
            let mint_info = &ctx.remaining_accounts[i + 2];
            let vault_token: InterfaceAccount<TokenAccount> =
                InterfaceAccount::try_from(vault_token_info)?;
            let owner_token: InterfaceAccount<TokenAccount> =
                InterfaceAccount::try_from(owner_token_info)?;
            let mint: InterfaceAccount<Mint> = InterfaceAccount::try_from(mint_info)?;

            if vault.allowed_mints.contains(&vault_token.mint)
                && vault_token.owner == ctx.accounts.vault_authority.key()
                && owner_token.owner == vault.owner
                && owner_token.mint == vault_token.mint
                && mint.key() == vault_token.mint
                && vault_token_info.owner == &ctx.accounts.token_program.key()
                && owner_token_info.owner == &ctx.accounts.token_program.key()
                && mint_info.owner == &ctx.accounts.token_program.key()
                && vault_token.amount > 0
            {
                let cpi_accounts = TransferChecked {
                    from: vault_token_info.clone(),
                    mint: mint_info.clone(),
                    to: owner_token_info.clone(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                };
                token_interface::transfer_checked(
                    CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        cpi_accounts,
                        &[signer_seeds],
                    ),
                    vault_token.amount,
                    mint.decimals,
                )?;
                emit!(FundsWithdrawn {
                    mint: vault_token.mint,
                    to: vault.owner,
                    amount: vault_token.amount,
                });
            }
            i += 3;
        }

        withdraw_vault_lamports(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.owner.to_account_info(),
        )?;
        Ok(())
    }

    pub fn withdraw_token(ctx: Context<WithdrawToken>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        require!(amount > 0, VaultError::InvalidInput);
        require!(
            ctx.accounts.vault_token_account.owner == ctx.accounts.vault_authority.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_account.mint == ctx.accounts.mint.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.recipient_token_account.mint == ctx.accounts.mint.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.recipient_token_account.owner == ctx.accounts.recipient_wallet.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.vault_token_account.to_account_info().owner
                == &ctx.accounts.token_program.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.recipient_token_account.to_account_info().owner
                == &ctx.accounts.token_program.key(),
            VaultError::BadAccount
        );
        require!(
            ctx.accounts.mint.to_account_info().owner == &ctx.accounts.token_program.key(),
            VaultError::BadAccount
        );
        require_vault_ata(
            &ctx.accounts.vault_authority.key(),
            &ctx.accounts.mint.key(),
            &ctx.accounts.token_program.key(),
            &ctx.accounts.vault_token_account.key(),
        )?;

        let vault_key = ctx.accounts.vault.key();
        let signer_seeds: &[&[u8]] = &[
            b"vault_authority",
            vault_key.as_ref(),
            &[vault.authority_bump],
        ];
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.vault_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.recipient_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                &[signer_seeds],
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        emit!(FundsWithdrawn {
            mint: ctx.accounts.mint.key(),
            to: ctx.accounts.recipient_wallet.key(),
            amount,
        });
        Ok(())
    }

    pub fn withdraw_native(ctx: Context<WithdrawNative>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::InvalidInput);
        let rent_min = Rent::get()?.minimum_balance(Vault::SPACE);
        let vault_lamports = ctx.accounts.vault.to_account_info().lamports();
        require!(
            vault_lamports >= rent_min + amount,
            VaultError::InsufficientBalance
        );

        **ctx
            .accounts
            .vault
            .to_account_info()
            .try_borrow_mut_lamports()? -= amount;
        **ctx
            .accounts
            .recipient
            .to_account_info()
            .try_borrow_mut_lamports()? += amount;
        emit!(FundsWithdrawn {
            mint: Pubkey::default(),
            to: ctx.accounts.recipient.key(),
            amount,
        });
        Ok(())
    }

    pub fn close_empty_token_accounts<'info>(
        ctx: Context<'_, '_, 'info, 'info, CloseEmptyTokenAccounts<'info>>,
    ) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let vault = &mut ctx.accounts.vault;
        require!(
            ctx.accounts.owner.key() == vault.owner,
            VaultError::Unauthorized
        );
        require!(
            ctx.remaining_accounts.len() % 2 == 0,
            VaultError::BadAccount
        );

        let signer_seeds: &[&[u8]] = &[
            b"vault_authority",
            vault_key.as_ref(),
            &[vault.authority_bump],
        ];

        let mut i = 0;
        while i < ctx.remaining_accounts.len() {
            let vault_token_info = &ctx.remaining_accounts[i];
            let mint_info = &ctx.remaining_accounts[i + 1];
            let vault_token: InterfaceAccount<TokenAccount> =
                InterfaceAccount::try_from(vault_token_info)?;
            let mint: InterfaceAccount<Mint> = InterfaceAccount::try_from(mint_info)?;
            require!(
                vault_token.owner == ctx.accounts.vault_authority.key(),
                VaultError::BadAccount
            );
            require!(vault_token.mint == mint.key(), VaultError::BadAccount);
            require!(vault_token.amount == 0, VaultError::TokenAccountNotEmpty);
            require!(
                vault_token_info.owner == &ctx.accounts.token_program.key(),
                VaultError::BadAccount
            );
            require!(
                mint_info.owner == &ctx.accounts.token_program.key(),
                VaultError::BadAccount
            );
            let expected_ata = associated_token_address_with_program(
                &ctx.accounts.vault_authority.key(),
                &mint.key(),
                &ctx.accounts.token_program.key(),
                &associated_token::ID,
            );
            require!(
                vault_token_info.key() == expected_ata,
                VaultError::BadAccount
            );

            let cpi_accounts = CloseAccount {
                account: vault_token_info.clone(),
                destination: ctx.accounts.owner.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            };
            token_interface::close_account(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
                &[signer_seeds],
            ))?;
            emit!(TokenAccountClosed {
                token_account: vault_token_info.key(),
                mint: mint.key(),
                to: vault.owner,
            });
            if let Some(pos) = vault
                .allowed_mints
                .iter()
                .position(|allowed| *allowed == mint.key())
            {
                vault.allowed_mints.swap_remove(pos);
                emit!(TokenStatusUpdated {
                    mint: mint.key(),
                    allowed: false,
                });
            }
            i += 2;
        }
        Ok(())
    }

    pub fn close_vault_account(ctx: Context<CloseVaultAccount>) -> Result<()> {
        require!(
            ctx.accounts.owner.key() == ctx.accounts.vault.owner,
            VaultError::Unauthorized
        );
        require!(
            ctx.accounts.vault.allowed_mints.is_empty(),
            VaultError::VaultNotReadyToClose
        );
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(init, payer = owner, space = Vault::SPACE, seeds = [b"vault", owner.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority; no data is stored here and it has no private key.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct ReadVault<'info> {
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct RemoveToken<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub vault_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct AddToken<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct Trade<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub caller: Signer<'info>,
    #[account(mut)]
    pub vault_token_in: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub vault_token_out: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: Must match vault.jupiter_router.
    pub jupiter_program: UncheckedAccount<'info>,
    pub token_program_in: Interface<'info, TokenInterface>,
    pub token_program_out: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawAll<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub caller: Signer<'info>,

    /// CHECK: Must equal vault.owner; receives SOL.
    #[account(mut)]
    pub owner: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawToken<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,

    pub owner: Signer<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub vault_token_account: InterfaceAccount<'info, TokenAccount>,

    /// CHECK: Arbitrary recipient wallet chosen by owner.
    pub recipient_wallet: UncheckedAccount<'info>,
    #[account(mut)]
    pub recipient_token_account: InterfaceAccount<'info, TokenAccount>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct WithdrawNative<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,

    /// CHECK: Arbitrary native SOL recipient chosen by owner.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CloseEmptyTokenAccounts<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// CHECK: PDA authority validated by seeds.
    #[account(seeds = [b"vault_authority", vault.key().as_ref()], bump = vault.authority_bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CloseVaultAccount<'info> {
    #[account(mut, has_one = owner, close = owner)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub bot_address: Pubkey,
    pub jupiter_router: Pubkey,
    pub authority_bump: u8,
    pub allowed_mints: Vec<Pubkey>,
}

impl Vault {
    pub const SPACE: usize = 8 + 32 + 32 + 32 + 1 + 4 + (32 * MAX_ALLOWED_MINTS);
}

fn require_bot_or_owner(vault: &Vault, signer: &Pubkey) -> Result<()> {
    require!(
        *signer == vault.owner || *signer == vault.bot_address,
        VaultError::Unauthorized
    );
    Ok(())
}

fn require_allowed(vault: &Vault, mint: &Pubkey) -> Result<()> {
    require!(
        vault.allowed_mints.contains(mint),
        VaultError::TokenNotAllowed
    );
    Ok(())
}

fn validate_trade_remaining_accounts<'info>(
    remaining_accounts: &'info [AccountInfo<'info>],
    vault_authority: &Pubkey,
    vault_token_in: &Pubkey,
    vault_token_out: &Pubkey,
    token_program_in: &Pubkey,
    token_program_out: &Pubkey,
) -> Result<()> {
    let mut has_authority = false;
    let mut has_token_in = false;
    let mut has_token_out = false;
    let mut has_token_program_in = false;
    let mut has_token_program_out = false;

    for account in remaining_accounts.iter() {
        let key = account.key();
        if key == *vault_authority {
            has_authority = true;
        }
        if key == *vault_token_in && account.is_writable {
            has_token_in = true;
        }
        if key == *vault_token_out && account.is_writable {
            has_token_out = true;
        }
        if key == *token_program_in {
            has_token_program_in = true;
        }
        if key == *token_program_out {
            has_token_program_out = true;
        }

        if account.is_writable
            && is_supported_token_account_owner(account.owner)
            && key != *vault_token_in
            && key != *vault_token_out
        {
            if let Ok(token_account) = InterfaceAccount::<TokenAccount>::try_from(account) {
                require!(
                    token_account.owner != *vault_authority,
                    VaultError::BadAccount
                );
            }
        }
    }

    require!(
        has_authority
            && has_token_in
            && has_token_out
            && has_token_program_in
            && has_token_program_out,
        VaultError::BadAccount
    );
    Ok(())
}

fn is_supported_token_account_owner(owner: &Pubkey) -> bool {
    <TokenAccount as anchor_lang::Owners>::owners().contains(owner)
}

fn ensure_vault_atas<'info>(
    remaining_accounts: &'info [AccountInfo<'info>],
    payer_info: &AccountInfo<'info>,
    vault_authority_info: &AccountInfo<'info>,
    system_program_info: &AccountInfo<'info>,
    associated_token_program_info: &AccountInfo<'info>,
    mints: &[Pubkey],
) -> Result<()> {
    require!(
        remaining_accounts.len() == mints.len() * 3,
        VaultError::BadAccount
    );
    for (index, expected_mint) in mints.iter().enumerate() {
        let base = index * 3;
        let mint_info = &remaining_accounts[base];
        let ata_info = &remaining_accounts[base + 1];
        let token_program_info = &remaining_accounts[base + 2];
        require!(mint_info.key() == *expected_mint, VaultError::BadAccount);
        require!(
            mint_info.owner == token_program_info.key,
            VaultError::BadAccount
        );
        require!(
            is_supported_token_account_owner(token_program_info.key),
            VaultError::BadAccount
        );

        let expected_ata = associated_token_address_with_program(
            &vault_authority_info.key(),
            expected_mint,
            token_program_info.key,
            &associated_token_program_info.key(),
        );
        require!(ata_info.key() == expected_ata, VaultError::BadAccount);

        let cpi_accounts = Create {
            payer: payer_info.clone(),
            associated_token: ata_info.clone(),
            authority: vault_authority_info.clone(),
            mint: mint_info.clone(),
            system_program: system_program_info.clone(),
            token_program: token_program_info.clone(),
        };
        associated_token::create_idempotent(CpiContext::new(
            associated_token_program_info.clone(),
            cpi_accounts,
        ))?;
    }
    Ok(())
}

fn require_vault_ata(
    vault_authority: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    token_account: &Pubkey,
) -> Result<()> {
    let expected_ata = associated_token_address_with_program(
        vault_authority,
        mint,
        token_program,
        &associated_token::ID,
    );
    require!(*token_account == expected_ata, VaultError::BadAccount);
    Ok(())
}

fn associated_token_address_with_program(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    associated_token_program: &Pubkey,
) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        associated_token_program,
    )
    .0
}

fn withdraw_vault_lamports(vault_info: &AccountInfo, recipient_info: &AccountInfo) -> Result<()> {
    let rent_min = Rent::get()?.minimum_balance(Vault::SPACE);
    let vault_lamports = vault_info.lamports();
    if vault_lamports > rent_min {
        let amount = vault_lamports - rent_min;
        **vault_info.try_borrow_mut_lamports()? -= amount;
        **recipient_info.try_borrow_mut_lamports()? += amount;
        emit!(FundsWithdrawn {
            mint: Pubkey::default(),
            to: recipient_info.key(),
            amount,
        });
    }
    Ok(())
}

#[event]
pub struct TokenStatusUpdated {
    pub mint: Pubkey,
    pub allowed: bool,
}

#[event]
pub struct BotAddressUpdated {
    pub old_bot: Pubkey,
    pub new_bot: Pubkey,
}

#[event]
pub struct RouterUpdated {
    pub jupiter_router: Pubkey,
}

#[event]
pub struct TradeExecuted {
    pub token_in: Pubkey,
    pub token_out: Pubkey,
    pub router: Pubkey,
    pub amount_in: u64,
    pub amount_spent: u64,
    pub amount_out: u64,
}

#[event]
pub struct FundsWithdrawn {
    pub mint: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}

#[event]
pub struct TokenAccountClosed {
    pub token_account: Pubkey,
    pub mint: Pubkey,
    pub to: Pubkey,
}

#[error_code]
pub enum VaultError {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid input")]
    InvalidInput,
    #[msg("Invalid token")]
    InvalidToken,
    #[msg("Invalid router")]
    InvalidRouter,
    #[msg("Too many tokens")]
    TooManyTokens,
    #[msg("Token not allowed")]
    TokenNotAllowed,
    #[msg("Token already allowed")]
    TokenAlreadyAllowed,
    #[msg("Bad account")]
    BadAccount,
    #[msg("Slippage")]
    Slippage,
    #[msg("Math")]
    Math,
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Token account is not empty")]
    TokenAccountNotEmpty,
    #[msg("Vault is not ready to close")]
    VaultNotReadyToClose,
}
