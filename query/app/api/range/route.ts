import { getBlockRangeAvail } from '@/app/utils/avail';
import { NextRequest, NextResponse } from 'next/server';

/** Get the range of blocks that the VectorX contract has emitted logs for.
 * Required query parameters:
 * - contractChainId: The chain ID where the VectorX contract is deployed.
 * - contractAddress: The address of the VectorX contract.
 */
export async function GET(req: NextRequest) {
    const url = new URL(req.url);

    const ethereumChainId = Number(url.searchParams.get('contractChainId'));
    const address = url.searchParams.get('contractAddress');

    console.log('Ethereum Chain ID: ' + ethereumChainId);
    console.log('VectorX Address: ' + address);

    if (ethereumChainId === undefined || address === undefined) {
        return NextResponse.json({
            success: false
        });
    }

    // Parse address from string to Uint8Array.
    const contractAddress = Buffer.from(address!.substring(2), 'hex');

    let range = await getBlockRangeAvail(contractAddress, ethereumChainId);
    if (range === undefined) {
        return NextResponse.json({
            success: false,
            error: 'Failed to get block range for requested block! This means that the specified contract is not registered in this service.'
        });
    } else {
        return NextResponse.json({
            data: range
        });
    }
}