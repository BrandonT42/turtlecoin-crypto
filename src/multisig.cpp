// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include "multisig.h"
#include "Varint.h"

namespace Crypto
{
    namespace Multisig
    {
        extern "C"
        {
#include "crypto-ops.h"
#include "keccak.h"
        }

        /* Checks if an arbitrary pod is a scalar */
        template<typename T>
        bool is_scalar(const T &key)
        {
            return !sc_check(reinterpret_cast<const unsigned char *>(key.data));
        }

        /* Used to sort a vector of keys so that they are always
           in the same order */
        template<typename T>
        void sortKeys(std::vector<T> &keys)
        {
            std::sort(keys.begin(), keys.end(), [](const T &a, const T &b){
                return memcmp(&a, &b, sizeof(a));
            });
        };

        /* Used to multiply two keys together */
        template<typename T, typename U, typename V>
        void scalarmultKey(const T &P, const U &a, V &aP)
        {
            ge_p3 A;
            ge_p2 R;
            // maybe use assert instead?
            ge_frombytes_vartime(&A, reinterpret_cast<const unsigned char *>(&P));
            ge_scalarmult(&R, reinterpret_cast<const unsigned char *>(&a), &A);
            ge_tobytes(reinterpret_cast<unsigned char *>(&aP), &R);
        };

        template<typename T>
        void addKeys(const T &a, const T &b, T &c)
        {
            if (!is_scalar(a))
            {
                ge_p3 b2;
                ge_p3 a2;
                ge_frombytes_vartime(&b2, reinterpret_cast<const unsigned char *>(b.data));
                ge_frombytes_vartime(&a2, reinterpret_cast<const unsigned char *>(a.data));
                ge_cached tmp2;
                ge_p3_to_cached(&tmp2, &b2);
                ge_p1p1 tmp3;
                ge_add(&tmp3, &a2, &tmp2);
                ge_p1p1_to_p3(&a2, &tmp3);
                ge_p3_tobytes(reinterpret_cast<unsigned char *>(c.data), &a2);
            }
            else
            {
                sc_add(
                    reinterpret_cast<unsigned char *>(&c),
                    reinterpret_cast<const unsigned char *>(&a),
                    reinterpret_cast<const unsigned char *>(&b));
            }
        };

        template<typename T>
        T addKeys(const std::vector<T> &keys)
        {
            if (keys.size() == 0)
            {
                return T();
            }
            else if (keys.size() == 1)
            {
                return keys.front();
            }

            T result = keys.front();

            for (auto i = 1; i < keys.size(); i++)
            {
                addKeys(result, keys.at(i), result);
            }

            return result;
        };

        template<typename T>
        T addKeys(const T &key, const std::vector<T> &keys)
        {
            std::vector<T> _keys;

            _keys.push_back(key);

            for (auto &_key : keys)
            {
                _keys.push_back(_key);
            }

            return addKeys(_keys);
        };

        static inline void hash_to_scalar(const void *data, size_t length, Crypto::EllipticCurveScalar &res)
        {
            cn_fast_hash(data, length, reinterpret_cast<Hash &>(res));
            sc_reduce32(reinterpret_cast<unsigned char *>(&res));
        }

        static void derivation_to_scalar(const Crypto::KeyDerivation &derivation, size_t output_index, Crypto::EllipticCurveScalar &res)
        {
            struct
            {
                Crypto::KeyDerivation derivation;
                char output_index[(sizeof(size_t) * 8 + 6) / 7];
            } buf;
            char *end = buf.output_index;
            buf.derivation = derivation;
            Tools::write_varint(end, output_index);
            hash_to_scalar(&buf, end - reinterpret_cast<char *>(&buf), res);
        }

        /* Public Methods */

        static uint32_t rounds_required(const uint32_t participants, uint32_t threshold)
        {
            return participants - threshold + 1;
        }

        void generate_n_n(
            const Crypto::PublicKey &ourPublicSpendKey,
            const Crypto::SecretKey &ourPrivateViewKey,
            const std::vector<Crypto::PublicKey> &publicSpendKeys,
            const std::vector<Crypto::SecretKey> &secretSpendKeys,
            Crypto::PublicKey &sharedPublicSpendKey,
            Crypto::SecretKey &sharedPrivateViewKey
        )
        {
            sharedPublicSpendKey = addKeys(ourPublicSpendKey, publicSpendKeys);

            sharedPrivateViewKey = addKeys(ourPrivateViewKey, secretSpendKeys);
        }

        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::KeyImage> &partialKeyImages
        )
        {
            Crypto::EllipticCurveScalar _derivationScalar;

            derivation_to_scalar(derivation, output_index, _derivationScalar);

            Crypto::SecretKey _derivation(_derivationScalar.data);

            Crypto::KeyImage baseKeyImage;

            Crypto::generate_key_image(publicEphemeral, _derivation, baseKeyImage);

            return addKeys(baseKeyImage, partialKeyImages);
        }
    } // namespace Multisig
} // namespace Crypto