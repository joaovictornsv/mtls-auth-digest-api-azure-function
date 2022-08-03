import { HttpRequestHeaders } from '@azure/functions'
import { createHash } from 'crypto'
import { NotAuthorizedException } from 'sidelab-http-exceptions';

interface IDigestAuthenticationInfo {
  user?: string;
  key?: string;
  iv?: string;
}

const STATIC_KEYS = {
  [process.env.V1_USER_KEY]: process.env.V1_STATIC_KEY,
  [process.env.V2_USER_KEY]: process.env.V2_STATIC_KEY
}

const GLOBAL_SECRET = process.env.GLOBAL_SECRET

const generateHash = (user: string, staticKey: string, iv: string) => {
  const hasher = createHash('sha256')
  const hash = hasher.update(`${user}:${staticKey}:${iv}:${GLOBAL_SECRET}`).digest('hex');
  return hash;
}

const parseAuthenticationInfo = (authData: string): IDigestAuthenticationInfo => {
  const authenticationObj = {};  

  const fields = authData.replace(/^Digest /, '');
  fields.split(', ').forEach((d) => {
    const pair = d.split('=');   
    authenticationObj[pair[0]] = pair[1]
  });

  return authenticationObj;
}

const validateDigestString = (value: string) => {
  const match =  value.match(/^Digest ((user|key|iv)=[a-zA-Z0-9-_]*, )*(user|key|iv)=[a-zA-Z0-9-_]*$/);
  if (!match) throw new Error('Provide a valid digest')
}

const getStaticKey = (value: string) => {
  if (!Object.keys(STATIC_KEYS).includes(value)) throw new Error( 'api user unauthorized')
  return STATIC_KEYS[value]
}

const extractDigestHeader = (headers: HttpRequestHeaders) => {
  const digest = headers['www-authenticate']
  if (!digest) throw new Error('Provide digest authentication')

  validateDigestString(digest)
  return digest
}

export const authDigest = (headers: HttpRequestHeaders) => {
  const digest = extractDigestHeader(headers)
  
  const parsed = parseAuthenticationInfo(digest)
  console.log(parsed)
  
  const { user, key, iv } = parsed
  const API_KEY_ESTATICA = getStaticKey(user)

  const API_KEY = generateHash(user, API_KEY_ESTATICA, iv);

  if (key !== API_KEY) throw new NotAuthorizedException('Invalid api key')
}

