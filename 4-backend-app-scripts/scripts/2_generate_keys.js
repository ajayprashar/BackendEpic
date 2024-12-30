import jose from 'node-jose'
import fs from 'fs'

const keyStore = jose.JWK.createKeyStore()
keyStore.generate('RSA', 2048, {alg: 'RS256', use: 'sig' })
.then(result => {
  fs.writeFileSync(
    'keys.json', 
    JSON.stringify(keyStore.toJSON(true), null, '  ')
  )
})

