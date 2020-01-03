// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

'use strict'

const assert = require('assert')
const describe = require('mocha').describe
const it = require('mocha').it
const TurtleCoinCrypto = require('../jsbuild/turtlecoin-crypto')()

describe('Cryptography', () => {
  describe('Core', () => {
    it('Generate Random Keys', () => {
      const keys = TurtleCoinCrypto.generateKeys()

      assert((keys))
    })

    it('Check Key - Public Key', () => {
      const key = '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac'
      const isValid = TurtleCoinCrypto.checkKey(key)

      assert(isValid === true)
    })

    it('Check Key - Private Key', () => {
      const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'
      const isValid = TurtleCoinCrypto.checkKey(key)

      assert(isValid === false)
    })

    it('Secret Key to Public Key', () => {
      const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'

      const generatedKey = TurtleCoinCrypto.secretKeyToPublicKey(key)

      assert(generatedKey === '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac')
    })

    it('Generate Key Derivation', () => {
      const derivation = TurtleCoinCrypto.generateKeyDerivation('3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94', '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909')

      assert(derivation === '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20')
    })

    it('Derive Public Key', () => {
      const publicKey = TurtleCoinCrypto.derivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')

      assert(publicKey === 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')
    })

    it('Underive Public Key: Ours', () => {
      const publicKey = TurtleCoinCrypto.underivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

      assert(publicKey === '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')
    })

    it('Underive Public Key: Not Ours', () => {
      const publicKey = TurtleCoinCrypto.underivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 0, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

      assert(publicKey !== '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')
    })

    it('Derive Secret Key', () => {
      const secretKey = TurtleCoinCrypto.deriveSecretKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, 'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b')

      assert(secretKey === 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e')
    })

    it('Generate Key Image', () => {
      const keyImage = TurtleCoinCrypto.generateKeyImage('bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d', 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e')

      assert(keyImage === '5997cf23543ce2e05c327297a47f26e710af868344859a6f8d65683d8a2498b0')
    })

    it('Generate Deterministic Subwallet #0', () => {
      const spendKey = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 0)

      assert(spendKey.secretKey === 'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c')
    })

    it('Generate Deterministic Subwallet #1', () => {
      const spendKey = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 1)

      assert(spendKey.secretKey === 'c55cbe4fd1c49dca5958fa1c7b9212c2dbf3fd5bfec84de741d434056e298600')
    })

    it('Generate Deterministic Subwallet #64', () => {
      const spendKey = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 64)

      assert(spendKey.secretKey === '29c2afed13271e2bb3321c2483356fd8798f2709af4de3906b6627ec71727108')
    })

    it('Tree Hash', () => {
      const expectedTreeHash = 'dff9b4e047803822e97fb25bb9acb8320648954e15a6ddf6fa757873793c535e'

      const hashes = new TurtleCoinCrypto.VectorString()

      const testHashes = [
        'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
        '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
        'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
        '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
      ]

      testHashes.forEach(item => hashes.push_back(item))

      const treeHash = TurtleCoinCrypto.tree_hash(hashes)

      assert(treeHash === expectedTreeHash)
    })

    it('Tree Branch', () => {
      const expectedTreeBranch = [
        'f49291f9b352701d97dffad838def8cefcc34d1e767e450558261b161ab78cb1',
        '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f'
      ]

      const hashes = new TurtleCoinCrypto.VectorString()

      const testHashes = [
        'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
        '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
        'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
        '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
      ]

      testHashes.forEach(item => hashes.push_back(item))

      const treeBranch = TurtleCoinCrypto.tree_branch(hashes)

      const results = []

      for (var i = 0; i < treeBranch.size(); i++) {
        results.push(treeBranch.get(i))
      }

      assert.deepStrictEqual(results, expectedTreeBranch)
    })
  })

  describe('Multisig', () => {
    const party1 = {
      spend: {
        secretKey: 'a0ba0cae34ce1133b9cb658e5d0a56440608622a64562ac360907a2c68ea130d',
        publicKey: '6bce43e0d797b9ee674db41c173f9b147fab6841fed36e97d434bd7c6f5b81d5'
      },
      view: {
        secretKey: '01d85bf9ce5583c7a1039f2c2695cb562bf1ea97636bbaf9051af01dddc89e0b',
        publicKey: 'fb2ecf5c9492863580d8ac90f04d114a29d536bed166d7e80a845a90c2ee1e54'
      }
    }

    const party2 = {
      spend: {
        secretKey: '91ace6308728a8e1c7d833b2fe9beb4a5a808ec04218e7da8402260a3872120d',
        publicKey: 'ba719ff6486ae5ab5ea0c7e05f6b42468f898bd366f83a4d165e396c1f7c5eec'
      },
      view: {
        secretKey: '650110a79f0353624f0fa14aaaf8c5af405ddb009c3127366e5b8591ecec9704',
        publicKey: '7e95331e33950119be42ac0b84ce2c39c99ff90982c6f022e44de8ede33ed4e1'
      }
    }

    /*
    const party3 = {
      spend: {
        secretKey: '42b79cc7ac0b05ef34cd08716efec28a73366b702fcc6a09c37f5428ee52a802',
        publicKey: 'fd524a5384bf5044feeb61f19866e11f74b8dbf5e7d050238046b04289a31849'
      },
      view: {
        secretKey: '4f94fe294c541a5fe9740fa96ae86d70df9f51b13fe88ae5188ae59aae71910b',
        publicKey: '366afc95bcb0bfa9fb2282078133b4bc618f193ba948cb0dd896a3405057eafd'
      }
    }
    */

    describe('N/N', () => {
      const sharedKeys = {
        spend: {
          secretKey: '4493fd81a193a7bcaa07a29d7dac627a6088f0eaa66e119ee592a036a05c260a',
          publicKey: 'caa8f9aaf673ff2c055025942eeefde720a71281420ec8c42f0a817225db032b'
        },
        view: {
          secretKey: '7905764354f6c3d11a7648d4f193b2f16b4ec698ff9ce12f747575afc9b53600',
          publicKey: '1b549cad10dfefe6c7cb1a7b707725ec914d2f87ba25337edb64b96c6a31d3ae'
        }
      }

      const tx = {
        input: {
          key: 'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0',
          index: 2
        },
        keys: {
          publicKey: '4a037147e1236c13e6bc2b6fbd17758b7333c613a38738e468b586008de1c13e'
        },
        derivation: '9475ebaa9f869b06d967aa0ca09d1632f4b8a383211c8a66e39021bc04d80fc4',
        publicEphemeral: 'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0',
        privateEphemeral: '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b',
        keyImage: '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0'
      }

      describe('Party 1', () => {
        it('Generate Shared Keys', () => {
          const pubs = new TurtleCoinCrypto.VectorString()
          pubs.push_back(party2.spend.publicKey)

          const privs = new TurtleCoinCrypto.VectorString()
          privs.push_back(party2.view.secretKey)

          const p1SharedKeys = TurtleCoinCrypto.generateNN(
            party1.spend.publicKey,
            party1.view.secretKey,
            pubs,
            privs
          )

          assert(p1SharedKeys.publicSpendKey === sharedKeys.spend.publicKey)
          assert(p1SharedKeys.secretViewKey === sharedKeys.view.secretKey)

          const publicViewKey = TurtleCoinCrypto.secretKeyToPublicKey(p1SharedKeys.secretViewKey)
          assert(publicViewKey === sharedKeys.view.publicKey)
        })
      })

      describe('Party 2', () => {
        it('Generate Shared Keys', () => {
          const pubs = new TurtleCoinCrypto.VectorString()
          pubs.push_back(party1.spend.publicKey)

          const privs = new TurtleCoinCrypto.VectorString()
          privs.push_back(party1.view.secretKey)

          const p2SharedKeys = TurtleCoinCrypto.generateNN(
            party2.spend.publicKey,
            party2.view.secretKey,
            pubs,
            privs
          )
          assert(p2SharedKeys.publicSpendKey === sharedKeys.spend.publicKey)
          assert(p2SharedKeys.secretViewKey === sharedKeys.view.secretKey)

          const publicViewKey = TurtleCoinCrypto.secretKeyToPublicKey(p2SharedKeys.secretViewKey)
          assert(publicViewKey === sharedKeys.view.publicKey)
        })

        it('Restore KeyImage from Partial KeyImages', () => {
          const keyImage1 = TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, party1.spend.secretKey)
          const keyImage2 = TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, party2.spend.secretKey)

          const keyImages = new TurtleCoinCrypto.VectorString()
          keyImages.push_back(keyImage1)
          keyImages.push_back(keyImage2)

          const keyImage = TurtleCoinCrypto.restoreKeyImage(tx.publicEphemeral, tx.derivation, tx.input.index, keyImages)
          assert(keyImage === tx.keyImage)
        })
      })
    })

    describe('N1/N', () => {

    })
  })
})

describe('Hash Generation Methods', function () {
  this.timeout(10000)

  const testdata = '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'

  const algos = [
    { name: 'CryptoNight Fast Hash', func: 'cn_fast_hash', hash: 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0' },
    { name: 'CryptoNight v0', func: 'cn_slow_hash_v0', hash: '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f' },
    { name: 'CryptoNight v1', func: 'cn_slow_hash_v1', hash: 'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122' },
    { name: 'CryptoNight v2', func: 'cn_slow_hash_v2', hash: '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578' },
    { name: 'CryptoNight Lite v0', func: 'cn_lite_slow_hash_v0', hash: '28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd' },
    { name: 'CryptoNight Lite v1', func: 'cn_lite_slow_hash_v1', hash: '87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f' },
    { name: 'CryptoNight Lite v2', func: 'cn_lite_slow_hash_v2', hash: 'b7e78fab22eb19cb8c9c3afe034fb53390321511bab6ab4915cd538a630c3c62' },
    { name: 'CryptoNight Dark v0', func: 'cn_dark_slow_hash_v0', hash: 'bea42eadd78614f875e55bb972aa5ec54a5edf2dd7068220fda26bf4b1080fb8' },
    { name: 'CryptoNight Dark v1', func: 'cn_dark_slow_hash_v1', hash: 'd18cb32bd5b465e5a7ba4763d60f88b5792f24e513306f1052954294b737e871' },
    { name: 'CryptoNight Dark v2', func: 'cn_dark_slow_hash_v2', hash: 'a18a14d94efea108757a42633a1b4d4dc11838084c3c4347850d39ab5211a91f' },
    { name: 'CryptoNight Dark Lite v0', func: 'cn_dark_lite_slow_hash_v0', hash: 'faa7884d9c08126eb164814aeba6547b5d6064277a09fb6b414f5dbc9d01eb2b' },
    { name: 'CryptoNight Dark Lite v1', func: 'cn_dark_lite_slow_hash_v1', hash: 'c75c010780fffd9d5e99838eb093b37c0dd015101c9d298217866daa2993d277' },
    { name: 'CryptoNight Dark Lite v2', func: 'cn_dark_lite_slow_hash_v2', hash: 'fdceb794c1055977a955f31c576a8be528a0356ee1b0a1f9b7f09e20185cda28' },
    { name: 'CryptoNight Turtle v0', func: 'cn_turtle_slow_hash_v0', hash: '546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982' },
    { name: 'CryptoNight Turtle v1', func: 'cn_turtle_slow_hash_v1', hash: '29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e' },
    { name: 'CryptoNight Turtle v2', func: 'cn_turtle_slow_hash_v2', hash: 'fc67dfccb5fc90d7855ae903361eabd76f1e40a22a72ad3ef2d6ad27b5a60ce5' },
    { name: 'CryptoNight Turtle Lite v0', func: 'cn_turtle_lite_slow_hash_v0', hash: '5e1891a15d5d85c09baf4a3bbe33675cfa3f77229c8ad66c01779e590528d6d3' },
    { name: 'CryptoNight Turtle Lite v1', func: 'cn_turtle_lite_slow_hash_v1', hash: 'ae7f864a7a2f2b07dcef253581e60a014972b9655a152341cb989164761c180a' },
    { name: 'CryptoNight Turtle Lite v2', func: 'cn_turtle_lite_slow_hash_v2', hash: 'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26' },
    { name: 'Chukwa', func: 'chukwa_slow_hash', hash: 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e' }
  ]

  algos.forEach((algo) => {
    it(algo.name, () => {
      const hash = TurtleCoinCrypto[algo.func](testdata)
      assert(algo.hash === hash)
    })
  })
})
