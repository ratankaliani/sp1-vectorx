import { CHAIN_TO_WS_ENDPOINT, getHealthStatusAvail } from '@/app/utils/avail';
import { NextRequest, NextResponse } from 'next/server';

/** Request the health of a VectorX light client. Searches for the latest log emitted by the VectorX
* contract and compares it to the latest block on the Avail chain. Also finds the difference between
* the latest block on the Avail chain and the latest block on the VectorX contract.

* Required query parameters:
* - chainName: The name of the Avail chain to check.
* - contractChainId: The chain ID where the VectorX contract is deployed.
* - contractAddress: The address of the VectorX contract.
* Optional query parameters:
* - maxDelayHours: The number of hours to check for emitted logs. Default is 4 hours.
*/
export async function GET(req: NextRequest) {
    const url = new URL(req.url);

    const chainName = url.searchParams.get('chainName');
    const ethereumChainId = Number(url.searchParams.get('contractChainId'));
    const address = url.searchParams.get('contractAddress');
    const maxDelayHours = Number(url.searchParams.get('maxDelayHours')) || 4;

    console.log('Avail Chain name: ' + chainName);
    console.log('Ethereum Chain ID: ' + ethereumChainId);
    console.log('Address: ' + address);

    if (ethereumChainId === undefined || address === undefined || chainName === undefined) {
        return NextResponse.json({
            success: false,
            error: 'Missing required parameters'
        });
    }

    if (process.env[`RPC_${ethereumChainId}`] === undefined) {
        return NextResponse.json({
            success: false,
            error: `Chain ID ${ethereumChainId} is not supported.`
        });
    }

    let chainNameLowercase = chainName?.toLowerCase() as string;

    if (!CHAIN_TO_WS_ENDPOINT.has(chainNameLowercase)) {
        return NextResponse.json({
            success: false,
            error: `Chain name ${chainNameLowercase} is not supported. Supported chains: ${Array.from(CHAIN_TO_WS_ENDPOINT.keys()).join(', ')}`
        });
    }

    // Strip `0x` from address
    const addressUint8Array = Buffer.from(address!.substring(2), 'hex');

    let healthInfo = await getHealthStatusAvail(
        addressUint8Array,
        ethereumChainId,
        chainName?.toUpperCase() as string,
        BigInt(maxDelayHours) * 60n * 60n
    );

    return NextResponse.json({
        data: healthInfo
    });
}
