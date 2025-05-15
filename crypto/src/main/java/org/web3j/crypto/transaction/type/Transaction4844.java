/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.crypto.transaction.type;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

import org.web3j.crypto.Blob;
import org.web3j.crypto.BlobUtils;
import org.web3j.crypto.Sign;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Numeric;

public class Transaction4844 extends Transaction1559 implements ITransaction {

    private final BigInteger maxFeePerBlobGas;
    private final List<Bytes> versionedHashes;
    private final Optional<List<Blob>> blobs;
    private final Optional<List<Bytes>> kzgProofs;
    private final Optional<List<Bytes>> kzgCommitments;

    protected Transaction4844(
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas,
            List<Bytes> versionedHashes) {
        super(chainId, nonce, gasLimit, to, value, data, maxPriorityFeePerGas, maxFeePerGas);
        this.maxFeePerBlobGas = maxFeePerBlobGas;
        this.versionedHashes = versionedHashes;
        this.blobs = Optional.empty();
        this.kzgCommitments = Optional.empty();
        this.kzgProofs = Optional.empty();
    }

    protected Transaction4844(
            List<Blob> blobs,
            List<Bytes> kzgCommitments,
            List<Bytes> kzgProofs,
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas,
            List<Bytes> versionedHashes) {
        super(chainId, nonce, gasLimit, to, value, data, maxPriorityFeePerGas, maxFeePerGas);
        this.maxFeePerBlobGas = maxFeePerBlobGas;
        this.versionedHashes = versionedHashes;
        this.blobs = Optional.ofNullable(blobs);
        this.kzgCommitments = Optional.ofNullable(kzgCommitments);
        this.kzgProofs = Optional.ofNullable(kzgProofs);
    }

    protected Transaction4844(
            List<Blob> blobsData,
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas) {
        super(chainId, nonce, gasLimit, to, value, data, maxPriorityFeePerGas, maxFeePerGas);
        this.maxFeePerBlobGas = maxFeePerBlobGas;
        this.blobs = Optional.ofNullable(blobsData);

        // Build commitments list
        List<Bytes> commitments = new ArrayList<Bytes>();
        if (blobsData != null) {
            for (Blob b : blobsData) {
                commitments.add(BlobUtils.getCommitment(b));
            }
        }
        this.kzgCommitments = Optional.of(commitments);

        // Build proofs list
        List<Bytes> proofs = new ArrayList<Bytes>();
        for (int i = 0; i < commitments.size(); i++) {
            proofs.add(BlobUtils.getProof(blobsData.get(i), commitments.get(i)));
        }
        this.kzgProofs = Optional.of(proofs);

        // Build versioned hashes list
        List<Bytes> hashes = new ArrayList<Bytes>();
        for (Bytes c : commitments) {
            hashes.add(BlobUtils.kzgToVersionedHash(c));
        }
        this.versionedHashes = hashes;
    }

    @Override
    public List<RlpType> asRlpValues(Sign.SignatureData signatureData) {
        List<RlpType> resultTx = new ArrayList<RlpType>();

        resultTx.add(RlpString.create(getChainId()));
        resultTx.add(RlpString.create(getNonce()));
        resultTx.add(RlpString.create(getMaxPriorityFeePerGas()));
        resultTx.add(RlpString.create(getMaxFeePerGas()));
        resultTx.add(RlpString.create(getGasLimit()));

        String to = getTo();
        if (to != null && to.length() > 0) {
            resultTx.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            resultTx.add(RlpString.create(""));
        }

        resultTx.add(RlpString.create(getValue()));
        byte[] dataBytes = Numeric.hexStringToByteArray(getData());
        resultTx.add(RlpString.create(dataBytes));

        // access list
        resultTx.add(new RlpList());

        // Blob Transaction: max_fee_per_blob_gas and versioned_hashes
        resultTx.add(RlpString.create(getMaxFeePerBlobGas()));
        resultTx.add(new RlpList(getRlpVersionedHashes()));

        if (signatureData != null) {
            resultTx.add(RlpString.create(Sign.getRecId(signatureData, getChainId())));
            resultTx.add(RlpString.create(org.web3j.utils.Bytes.trimLeadingZeroes(signatureData.getR())));
            resultTx.add(RlpString.create(org.web3j.utils.Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        List<RlpType> wrapped = new ArrayList<RlpType>();
        wrapped.add(new RlpList(resultTx));

        // Adding blobs, commitments, and proofs
        wrapped.add(new RlpList(getRlpBlobs()));
        wrapped.add(new RlpList(getRlpKzgCommitments()));
        wrapped.add(new RlpList(getRlpKzgProofs()));

        return wrapped;
    }

    public static Transaction4844 createTransaction(
            List<Blob> blobs,
            List<Bytes> kzgCommitments,
            List<Bytes> kzgProofs,
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas,
            List<Bytes> versionedHashes) {

        return new Transaction4844(
                blobs,
                kzgCommitments,
                kzgProofs,
                chainId,
                nonce,
                maxPriorityFeePerGas,
                maxFeePerGas,
                gasLimit,
                to,
                value,
                data,
                maxFeePerBlobGas,
                versionedHashes);
    }

    public static Transaction4844 createTransaction(
            List<Blob> blobs,
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas) {

        return new Transaction4844(
                blobs,
                chainId,
                nonce,
                maxPriorityFeePerGas,
                maxFeePerGas,
                gasLimit,
                to,
                value,
                data,
                maxFeePerBlobGas);
    }

    public static Transaction4844 createTransaction(
            long chainId,
            BigInteger nonce,
            BigInteger maxPriorityFeePerGas,
            BigInteger maxFeePerGas,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            BigInteger maxFeePerBlobGas,
            List<Bytes> versionedHashes) {

        return new Transaction4844(
                chainId,
                nonce,
                maxPriorityFeePerGas,
                maxFeePerGas,
                gasLimit,
                to,
                value,
                data,
                maxFeePerBlobGas,
                versionedHashes);
    }

    public BigInteger getMaxFeePerBlobGas() {
        return maxFeePerBlobGas;
    }

    public Optional<List<Blob>> getBlobs() {
        return blobs;
    }

    public Optional<List<Bytes>> getKzgCommitments() {
        return kzgCommitments;
    }

    public Optional<List<Bytes>> getKzgProofs() {
        return kzgProofs;
    }

    public List<Bytes> getVersionedHashes() {
        return versionedHashes;
    }

    public List<RlpType> getRlpVersionedHashes() {
        List<RlpType> list = new ArrayList<RlpType>();
        for (Bytes hash : versionedHashes) {
            list.add(RlpString.create(hash.toArray()));
        }
        return list;
    }

    public List<RlpType> getRlpKzgCommitments() {
        if (kzgCommitments.isPresent()) {
            List<RlpType> list = new ArrayList<RlpType>();
            for (Bytes b : kzgCommitments.get()) {
                list.add(RlpString.create(b.toArray()));
            }
            return list;
        }
        return Collections.emptyList();
    }

    public List<RlpType> getRlpKzgProofs() {
        if (kzgProofs.isPresent()) {
            List<RlpType> list = new ArrayList<RlpType>();
            for (Bytes b : kzgProofs.get()) {
                list.add(RlpString.create(b.toArray()));
            }
            return list;
        }
        return Collections.emptyList();
    }

    public List<RlpType> getRlpBlobs() {
        if (blobs.isPresent()) {
            List<RlpType> list = new ArrayList<RlpType>();
            for (Blob blob : blobs.get()) {
                list.add(RlpString.create(blob.getData().toArray()));
            }
            return list;
        }
        return Collections.emptyList();
    }

    @Override
    public TransactionType getType() {
        return TransactionType.EIP4844;
    }
}
