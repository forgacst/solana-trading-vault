const crypto = require('crypto');
const {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction
} = require('@solana/web3.js');

const RPC = 'https://api.mainnet-beta.solana.com';

const PROGRAM_ID = new PublicKey(
  'EjKyCEqT3GkDP6PJajYqjrsWQNosfYFWZE2US2rWp7bR'
);

const VAULT = new PublicKey(
   process.argv[2] || '2PRS6x585h3CM3VzpxNXzpc2234A7DiKTwzrreq4Y6ow'
);

const discriminator = crypto
  .createHash('sha256')
  .update('global:get_allowed_tokens')
  .digest()
  .subarray(0, 8);

(async () => {
  const connection = new Connection(RPC, 'confirmed');

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      {
        pubkey: VAULT,
        isSigner: false,
        isWritable: false
      }
    ],
    data: discriminator
  });

  const latest = await connection.getLatestBlockhash('confirmed');

  const tx = new Transaction({
    feePayer: new PublicKey(
      'CG7EJzujE4PWF8qYYuRz29McZnYCZ1BEKqeiSgaBVFWK'
    ),
    recentBlockhash: latest.blockhash
  }).add(ix);

  const encoded = tx.serialize({
    requireAllSignatures: false,
    verifySignatures: false
  }).toString('base64');

  const result = await connection._rpcRequest(
    'simulateTransaction',
    [
      encoded,
      {
        encoding: 'base64',
        sigVerify: false,
        commitment: 'confirmed'
      }
    ]
  );

  if (result.error) {
    console.dir(result.error, {depth: null});
    process.exit(1);
  }

  const value = result.result.value;

  console.log('Simulation error:', value.err);

  if (value.err) {
    console.log(value.logs);
    process.exit(1);
  }

  if (!value.returnData) {
    console.log('No returnData');
    console.log(value.logs);
    process.exit(1);
  }

  const data = Buffer.from(value.returnData.data[0], 'base64');

  const count = data.readUInt32LE(0);

  console.log('Allowed tokens:', count);

  for (let i = 0; i < count; i++) {
    const start = 4 + i * 32;
    const mint = new PublicKey(
      data.subarray(start, start + 32)
    );

    console.log(`${i + 1}. ${mint.toBase58()}`);
  }
})();
