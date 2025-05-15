/*
 * Copyright 2019 Web3 Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.web3j.abi;

import java.util.List;

import org.web3j.abi.datatypes.CustomError;
import org.web3j.abi.datatypes.Type;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

/**
 * Ethereum custom error encoding. Further limited details are available <a
 * href="https://docs.soliditylang.org/en/develop/abi-spec.html#errors">here</a>.
 */
public class CustomErrorEncoder {

    private CustomErrorEncoder() {}

    public static String encode(CustomError error) {
        return calculateSignatureHash(buildErrorSignature(error.getName(), error.getParameters()));
    }

    static <T extends Type> String buildErrorSignature(
            String errorName, List<TypeReference<T>> parameters) {

        StringBuilder result = new StringBuilder();
        result.append(errorName);
        result.append("(");

        // Manually join with commas instead of streams + Collectors.joining
        for (int i = 0; i < parameters.size(); i++) {
            result.append(Utils.getTypeName(parameters.get(i)));
            if (i < parameters.size() - 1) {
                result.append(",");
            }
        }

        result.append(")");
        return result.toString();
    }

    public static String calculateSignatureHash(String errorSignature) {
        byte[] input = errorSignature.getBytes();
        byte[] hash = Hash.sha3(input);
        return Numeric.toHexString(hash);
    }
}
