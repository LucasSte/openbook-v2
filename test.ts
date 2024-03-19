
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey, Transaction } from '@solana/web3.js';
import * as openbook from '@openbook-dex/openbook-v2';
import { Program, BN, AnchorProvider, Wallet } from '@coral-xyz/anchor';
import * as splToken from "@solana/spl-token";

import * as fs from 'fs';

async function createMint(connection : Connection,  authority: Keypair, nb_decimals = 6) : Promise<PublicKey> {
    const kp = Keypair.generate();
    return await splToken.createMint(connection, 
        authority, 
        authority.publicKey, 
        authority.publicKey, 
        nb_decimals,
        kp)
}

export async function main() {

    const secretKey = JSON.parse(fs.readFileSync("/Users/lucasste/.config/solana/id.json", "utf-8"));
    const keypair = Keypair.fromSecretKey(new Uint8Array(secretKey));
    const authority = keypair;
    const payer = authority;
    const connection = new Connection("http://127.0.0.1:8899", "confirmed");


    let airdrop_sig = await connection.requestAirdrop(authority.publicKey, 2 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(airdrop_sig);

    let baseMint = await createMint(connection, authority, 6);
    let quoteMint = await createMint(connection, authority, 6);

    const quoteLotSize = new BN(1000000);
    const baseLotSize = new BN(1000000000);
    const makerFee = new BN(0);
    const takerFee = new BN(0);
    const timeExpiry = new BN(0);

    const wallet = new Wallet(authority);

    const programId = new PublicKey("5P9HphA5ts6r3779w3QMHooTuaFHptJehak6uszVcBve");
    const provider = new AnchorProvider(connection, wallet, {});
    let client = new openbook.OpenBookV2Client( provider, programId);

    // Add your test here.
    const [[bidIx, askIx, eventHeapIx, ix], [market, bidsKeypair, askKeypair, eventHeapKeypair]] = await client.createMarketIx(
      authority.publicKey,
      "Market Name",
      quoteMint,
      baseMint,
      quoteLotSize,
      baseLotSize,
      makerFee,
      takerFee,
      timeExpiry,
      null, // oracleA
      null, // oracleB
      null, // openOrdersAdmin
      null, // consumeEventsAdmin
      null, // closeMarketAdmin
    );
    console.log("sending tx");

    let tx = new Transaction();
    tx.add(bidIx);
    tx.add(askIx);
    tx.add(eventHeapIx);
    tx.add(ix);
    tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
    // Send transaction
    let sig = await connection.sendTransaction(tx, [authority, market, bidsKeypair, askKeypair, eventHeapKeypair], {
        skipPreflight: false
    });
    console.log('Your transaction signature', sig);
    await connection.confirmTransaction(sig);
    let logs = await connection.getParsedTransaction(sig);
    console.log(logs);
    
    // console.log("Market initialized successfully");
    // console.log("Market account:", market.publicKey.toBase58());
    // console.log("Bids account:", bidsKeypair.publicKey.toBase58());
    // console.log("Asks account:", askKeypair.publicKey.toBase58());
    // console.log("Event heap account:", eventHeapKeypair.publicKey.toBase58());
    // // console.log("Market authority:", market.authority.toBase58());
    // console.log("Quote mint:", quoteMint.toBase58());
    // console.log("Base mint:", baseMint.toBase58());
    // console.log("Quote lot size:", quoteLotSize.toString());
    // console.log("Base lot size:", baseLotSize.toString());
}

main().then(x => {
    console.log('finished sucessfully')
})