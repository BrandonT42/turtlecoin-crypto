// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
#pragma once

#include "crypto.h"
#include <iostream>

namespace Crypto
{
    namespace Multisig
    {
        /* Calculates the number of multisig rounds required */
        static uint32_t rounds_required(const uint32_t participants, uint32_t threshold);

        /* Generates the keys required for a N:N wallet by adding
           the private view keys and public spend keys together */
        void generate_n_n(
            const Crypto::PublicKey &ourPublicSpendKey,
            const Crypto::SecretKey &ourPrivateViewKey,
            const std::vector<Crypto::PublicKey> &publicSpendKeys,
            const std::vector<Crypto::SecretKey> &secretSpendKeys,
            Crypto::PublicKey &sharedPublicSpendKey,
            Crypto::SecretKey &sharedPrivateViewKey
        );

        Crypto::KeyImage restore_key_image(
            const Crypto::PublicKey &publicEphemeral,
            const Crypto::KeyDerivation &derivation,
            const size_t output_index,
            const std::vector<Crypto::KeyImage> &partialKeyImages
        );
    } // namespace Multisig
} // namespace Crypto