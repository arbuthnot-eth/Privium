import { createEnsPublicClient } from '@ensdomains/ensjs'
import { http } from 'viem'
import { mainnet } from 'viem/chains'
import { chainToCoinType } from './Privy/walletUtils'

export async function getPrivyWallets(privyUser: PrivyUser): Promise<any | any[]> {
    return privyUser.linkedAccounts.filter((acc) => acc.type === 'wallet' && acc.walletClientType === 'privy')
}


export async function translateENS(ens: string, chain: string): Promise<string | null> {
    const coinType = chainToCoinType[chain.toLowerCase()];
    if (!coinType) throw new Error(`Unsupported chain: ${chain}`);
  
    // Automatically append '.eth' if the input doesn't end with it (case-insensitive)
    if (!ens.toLowerCase().endsWith('.eth')) {
      ens = `${ens}.eth`;
    }
  
    const rpcUrl = process.env.ETH_RPC_URL || 'https://ethereum-rpc.publicnode.com';
    const client = createEnsPublicClient({
      chain: mainnet,
      transport: http(rpcUrl),
    });
  
    try {
      const record = await client.getAddressRecord({ name: ens, coin: coinType });
      if (!record?.value) throw new Error(`No address found for ENS ${ens} on chain ${chain}`);
      return record.value;
    } catch (error) {
      throw new Error(`ENS resolution failed for ${ens} on ${chain}: ${(error as Error).message}`);
    }
  }