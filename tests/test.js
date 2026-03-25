const {Keypair} = require('@solana/web3.js');
const {searcher} = require('../dist');

const jitoUrl = 'mainnet.block-engine.jito.wtf';

const authKeypair = Keypair.generate();
// const authKeypair = Keypair.fromSecretKey(Buffer.from([]))

async function main() {
  const client = searcher.searcherClient(jitoUrl, authKeypair);
  await client.init();
  const accounts = await client.getTipAccounts();
  console.log('tip accounts:', accounts);

  return;
}

main().catch(err => {
  console.log('---', err);
});
