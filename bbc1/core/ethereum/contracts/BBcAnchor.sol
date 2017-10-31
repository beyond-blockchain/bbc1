/*
Copyright (c) 2017 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
pragma solidity ^0.4.8;

contract BBcAnchor {

    mapping (uint256 => uint) public _digests;

    event Stored(uint256 indexed digest, uint block_no);
    
    function BBcAnchor() {
    }

    function getStored(uint256 digest) returns (uint block_no) {
        return (_digests[digest]);
    }

    function isStored(uint256 digest) returns (bool isStored) {
        return (_digests[digest] > 0);
    }

    function store(uint256 digest) returns (bool isAlreadyStored) {

        bool isRes = _digests[digest] > 0;

        if (!isRes) {
            _digests[digest] = block.number;
            Stored(digest, _digests[digest]);
        }

        return (isRes);
    }
}

/* end of BBcAnchor.sol */
