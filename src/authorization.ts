import base64 from 'base64-js';
import blakejs from 'blakejs';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
import { v4 as uuidv4 } from 'uuid';
import { bap_id, bap_public_key, bap_private_key, bap_unique_key_id, bpp_id, bpp_public_key, bpp_private_key, bpp_unique_key_id, logistic_id, logistic_public_key, logistic_private_key, logistic_unique_key_id } from './env'

export function hash_message(msg: string): string {
    const hasher = blakejs.blake2bInit(64);
    blakejs.blake2bUpdate(hasher, naclUtil.decodeUTF8(msg));
    const digest = blakejs.blake2bFinal(hasher);
    const digestStr = naclUtil.encodeBase64(digest);
    return digestStr;
}

export function create_signing_string(digestBase64: string, created?: number | null, expires?: number | null): string {
    if (created === null) {
        created = Math.floor(Date.now() / 1000);
    }
    if (expires === null) {
        expires = Math.floor((Date.now() + (1 * 60 * 60 * 1000)) / 1000);
    }
    const signingString = `(created): ${created}
(expires): ${expires}
digest: BLAKE-512=${digestBase64}`;
    return signingString;
}

export function sign_response(signingKey: string, privateKey: string): string {
    const privateKeyBytes = base64.toByteArray(privateKey);
    const signingKeyPair = nacl.sign.keyPair.fromSecretKey(privateKeyBytes);
    const signingKeyBytes = signingKeyPair.secretKey;
    const signed = nacl.sign.detached(naclUtil.decodeUTF8(signingKey), signingKeyBytes);
    const signature = naclUtil.encodeBase64(signed);
    return signature;
}

function addBase64Padding(base64String: string): string {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    return base64String + padding;
}

export function verify_response(signature: string, signingKey: string, publicKey: string): boolean {
    try {
        const publicKeyBytes = base64.toByteArray(publicKey);
        const paddedSignature = addBase64Padding(signature);
        const signatureBytes = base64.toByteArray(paddedSignature);
        nacl.sign.detached.verify(naclUtil.decodeUTF8(signingKey), signatureBytes, publicKeyBytes);
        return true;
    } catch (error) {
        return false;
    }
}

export function get_filter_dictionary_or_operation(filterString: string): Record<string, string> {
    const filterStringList = filterString.split(',').map((item) => item.trim());
    const filterDictionaryOrOperation: Record<string, string> = {};
    for (const fs of filterStringList) {
        const splits = fs.split('=', 2);
        const key = splits[0].trim();
        const value = splits[1].trim().replace(/"/g, '');
        filterDictionaryOrOperation[key] = value;
    }
    return filterDictionaryOrOperation;
}

export function create_authorisation_header({ requestBody, created, expires, type = 'bap' }: { requestBody: Record<string, any>, created?: number | null, expires?: number | null, type: string }): string {
    created = created || Math.floor(Date.now() / 1000);
    expires = expires || Math.floor((Date.now() + 3600000) / 1000);

    let id, uniqueKey, privateKey;
    switch (type) {
        case 'bap':
            id = bap_id
            uniqueKey = bap_unique_key_id
            privateKey = bap_private_key
            break;
        case 'bpp':
            id = bpp_id
            uniqueKey = bpp_unique_key_id
            privateKey = bpp_private_key
            break;
        case 'logistic':
            id = logistic_id
            uniqueKey = logistic_unique_key_id
            privateKey = logistic_private_key
            break;
    }
    const signingKey = create_signing_string(hash_message(JSON.stringify(requestBody)), created, expires);
    const signature = sign_response(signingKey, privateKey);
    const subscriberId = id;
    const uniqueKeyId = uniqueKey
    const header = `Signature keyId="${subscriberId}|${uniqueKeyId}|ed25519",algorithm="ed25519",created="${created}",expires="${expires}",headers="(created) (expires) digest",signature="${signature}"`;
    return header;
}

export function verify_authorisation_header({ authHeader, requestBody, created, expires, type = 'bap' }: { authHeader: string, requestBody: Record<string, any>, created?: number | null, expires?: number | null, type: string }): boolean {
    const headerParts = get_filter_dictionary_or_operation(authHeader.replace('Signature ', ''));
    const signingKey = create_signing_string(hash_message(JSON.stringify(requestBody)), created, expires);

    let id, uniqueKey, publicKey;
    switch (type) {
        case 'bap':
            id = bap_id
            uniqueKey = bap_unique_key_id
            publicKey = bap_public_key
            break;
        case 'bpp':
            id = bpp_id
            uniqueKey = bpp_unique_key_id
            publicKey = bpp_public_key
            break;
        case 'logistic':
            id = logistic_id
            uniqueKey = logistic_unique_key_id
            publicKey = logistic_public_key
            break;
    }
    return verify_response(headerParts.signature, signingKey, publicKey);
}

export function generate_key_pairs(): { privateKey: string; publicKey: string } {
    const signingKeyPair = nacl.sign.keyPair();
    const privateKey = base64.fromByteArray(signingKeyPair.secretKey);
    const publicKey = base64.fromByteArray(signingKeyPair.publicKey);
    return { privateKey, publicKey };
}

export function sign_registry_request(request: Record<string, any>): string {
    const reqObj: any[] = [];
    if (request.country) reqObj.push(request.country);
    if (request.domain) reqObj.push(request.domain);
    if (request.type) reqObj.push(request.type);
    if (request.city) reqObj.push(request.city);
    if (request.subscriber_id) reqObj.push(request.subscriber_id);

    const signingString = reqObj.join('|');
    return sign_response(signingString, bap_private_key);
}

export function format_registry_request(request: Record<string, any>): Record<string, any> {
    request.type = 'gateway';
    const signature = sign_registry_request(request);
    return {
        sender_subscriber_id: bap_id,
        request_id: uuidv4(),
        timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        search_parameters: request,
        signature,
    };
}

export function test_authorisation() {
    const request_body1: Record<string, any> = {
        context: {
            domain: 'nic2004:60212',
            country: 'IND',
            city: 'Kochi',
            action: 'search',
            core_version: '0.9.1',
            bap_id: 'bap.stayhalo.in',
            bap_uri: 'https://8f9f-49-207-209-131.ngrok.io/protocol/',
            transaction_id: 'e6d9f908-1d26-4ff3-a6d1-3af3d3721054',
            message_id: 'a2fe6d52-9fe4-4d1a-9d0b-dccb8b48522d',
            timestamp: '2022-01-04T09:17:55.971Z',
            ttl: 'P1M',
        },
        message: {
            intent: {
                fulfillment: {
                    start: {
                        location: {
                            gps: '10.108768, 76.347517',
                        },
                    },
                    end: {
                        location: {
                            gps: '10.102997, 76.353480',
                        },
                    },
                },
            },
        },
    };
    const auth_header1 = create_authorisation_header({ requestBody: request_body1, created: 1689620709, expires: 1689624309, type: 'logistic' });
    console.log(auth_header1);
    console.log(verify_authorisation_header({ authHeader: auth_header1, requestBody: request_body1, created: 1689620709, expires: 1689624309, type: 'bap' }));
}