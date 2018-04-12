# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import fractions
import hashlib
import sys
import time

sys.path.append("../../")

from bbc1.app import app_support_lib
from bbc1.core import bbclib
from bbc1.core import logger, bbc_app
from bbc1.core.bbc_error import *
from bbc1.core.message_key_types import KeyType
from bbc1.core.bbc_config import DEFAULT_CORE_PORT


NAME_OF_DB = 'token_db'


token_tx_id_table_definition = [
    ["tx_id", "BLOB"],
    ["tx", "BLOB"],
]

token_utxo_table_definition = [
    ["mint_id", "BLOB"],
    ["user_id", "BLOB"],
    ["tx_id", "BLOB"],
    ["event_idx", "INTEGER"],
    ["asset_body", "BLOB"],
    ["is_single", "INTEGER"],
    ["state", "INTEGER"],
    ["last_modified", "INTEGER"]
]

IDX_MINT_ID       = 0
IDX_USER_ID       = 1
IDX_TX_ID         = 2
IDX_EVENT_IDX     = 3
IDX_ASSET_BODY    = 4
IDX_IS_SINGLE     = 5
IDX_STATE         = 6
IDX_LAST_MODIFIED = 7

ST_FREE     = 0
ST_RESERVED = 1
ST_TAKEN    = 2


class Fraction(fractions.Fraction):

    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, sign = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, numerator = bbclib.get_n_byte_int(ptr, 2, data)
            ptr, denominator = bbclib.get_n_byte_int(ptr, 2, data)
        except:
            raise
        if sign > 0:
            numerator *= -1
        return ptr, Fraction(numerator, denominator)


    def is_positive_or_zero(self):
        return True if self.numerator >= 0 else False


    def serialize(self):
        if self.numerator < 0:
            dat = bytearray(bbclib.to_1byte(1))
            dat.extend(bbclib.to_2byte(-self.numerator))
        else:
            dat = bytearray(bbclib.to_1byte(0))
            dat.extend(bbclib.to_2byte(self.numerator))
        dat.extend(bbclib.to_2byte(self.denominator))
        return bytes(dat)


    def __add__(self, other):
        if isinstance(other, int):
            return (Fraction(self.numerator + other * self.denominator,
                    self.denominator))
        else:
            raise TypeError('must be int')


    def __mul__(self, other):
        if isinstance(other, Fraction):
            return (Fraction(self.numerator * other.numerator,
                    self.denominator * other.denominator))
        elif isinstance(other, int):
            return (other * self.numerator) // self.denominator
        else:
            raise TypeError('must be Fraction or int')


    def __pow__(self, n):
        if isinstance(n, int):
            return (Fraction(self.numerator ** n, self.denominator ** n))
        else:
            raise TypeError('must be int')


class Variation:

    T_SIMPLE = 0
    T_COMPOUND = 1


    def __init__(self, condition=0, type=T_SIMPLE, rate=None,
            rate_to_stop=None, time_unit=0x7fffffffffffffff, expire_after=0):
        if rate is None:
            rate = Fraction(0, 1)
        if rate_to_stop is None:
            rate_to_stop = Fraction(1, 1)
        self.condition = condition
        self.type = type
        self.rate = rate
        self.rate_to_stop = rate_to_stop
        self.time_unit = time_unit
        self.expire_after = expire_after


    def __eq__(self, other):
        return self.condition == other.condition and self.type == other.type \
                and self.rate == other.rate \
                and self.rate_to_stop == other.rate_to_stop \
                and self.time_unit == other.time_unit \
                and self.expire_after == other.expire_after


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, condition = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, type = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, rate = Fraction.from_serialized_data(ptr, data)
            ptr, rate_to_stop = Fraction.from_serialized_data(ptr, data)
            ptr, time_unit = bbclib.get_n_byte_int(ptr, 8, data)
            ptr, expire_after = bbclib.get_n_byte_int(ptr, 8, data)
        except:
            raise
        return ptr, Variation(condition, type, rate, rate_to_stop, time_unit,
                expire_after)


    def get_value(self, value_specified, time):
        if self.expire_after > 0 and time >= self.expire_after:
            return 0

        value_to_stop = self.rate_to_stop * value_specified

        if self.type == Variation.T_SIMPLE:
            value = value_specified \
                    + (self.rate * Fraction(time // self.time_unit, 1)) \
                    * value_specified
        elif self.type == Variation.T_COMPOUND:
            value = (self.rate + 1) ** (time // self.time_unit) \
                    * value_specified
        else:
            raise TypeError('unknown variation type')

        if self.rate.is_positive_or_zero():
            return value_to_stop if value > value_to_stop else value
        else:
            return value_to_stop if value < value_to_stop else value


    def get_next_update_time_relative_to_origin(self, time):
        time_update = self.time_unit * (time // self.time_unit + 1)
        return time_update \
                if self.expire_after <= 0 or time_update < self.expire_after \
                else self.expire_after


    def serialize(self):
        dat = bytearray(bbclib.to_1byte(self.condition))
        dat.extend(bbclib.to_1byte(self.type))
        dat.extend(self.rate.serialize())
        dat.extend(self.rate_to_stop.serialize())
        dat.extend(bbclib.to_8byte(self.time_unit))
        dat.extend(bbclib.to_8byte(self.expire_after))
        return bytes(dat)


class BaseAssetBody:

    T_VALUE   = 0b0000
    T_CHANGE  = 0b0001
    T_REFUND  = 0b0010
    T_ISSUED  = 0b0100
    T_VARIED  = 0b0101
    T_EXPIRED = 0b0110


    def __init__(self, type, value_specified, time_of_origin, variation_specs):
        self.type = type
        self.value_specified = value_specified
        self.time_of_origin = time_of_origin
        self.variation_specs = variation_specs


    def apply(self, transaction):
        return


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, type = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, value_specified = bbclib.get_n_byte_int(ptr, 8, data)
            ptr, time_of_origin = bbclib.get_n_byte_int(ptr, 8, data)
            ptr, count = bbclib.get_n_byte_int(ptr, 1, data)
            variation_specs = []
            for i in range(count):
                ptr, variation = Variation.from_serialized_data(ptr, data)
                variation_specs.append(variation)
        except:
            raise
        if type == BaseAssetBody.T_VALUE:
            obj = ValueAssetBody(value_specified, time_of_origin,
                    variation_specs)
        elif type == BaseAssetBody.T_CHANGE:
            obj = ChangeAssetBody(value_specified, time_of_origin,
                    variation_specs)
        elif type == BaseAssetBody.T_ISSUED:
            obj = IssuedAssetBody(value_specified, time_of_origin,
                    variation_specs)
        return ptr, obj


    def get_effective_value(self, time, condition=0):
        if len(self.variation_specs) == 0:
            return self.value_specified

        time -= self.time_of_origin
        if time < 0:
            time = 0

        return self.get_variation(condition).get_value(self.value_specified,
                time)


    def get_expected_loss_or_gain(self, time, condition=0):
        time_update = self.get_next_update_time(time, condition)
        value1 = self.get_effective_value(time_update, condition)
        value0 = self.get_effective_value(time, condition)

        return value0, (value1 - value0) / (time_update - time)


    '''
    This does not consider stop value.
    '''
    def get_next_update_time(self, time, condition=0):
        if len(self.variation_specs) == 0:
            return 0x7fffffffffffffff

        time -= self.time_of_origin
        if time < 0:
            time = 0

        time_update = self.get_variation(
                condition).get_next_update_time_relative_to_origin(time)

        return (self.time_of_origin + time_update) \
                if time < time_update else 0x7fffffffffffffff


    def get_variation(self, condition=0):
        for variation in self.variation_specs:
            if variation.condition == condition:
                return variation
        raise ValueError('condition %d is not found' % (condition))


    def is_same_spec(self, time_of_origin, variation_specs):
        if self.time_of_origin != time_of_origin:
            return False
        if len(self.variation_specs) != len(variation_specs):
            return False
        for i, variation_spec in enumerate(self.variation_specs):
            if variation_spec != variation_specs[i]:
                return False
        return True


    def serialize(self):
        dat = bytearray(bbclib.to_1byte(self.type))
        dat.extend(bbclib.to_8byte(self.value_specified))
        dat.extend(bbclib.to_8byte(self.time_of_origin))
        dat.extend(bbclib.to_1byte(len(self.variation_specs)))
        for variation in self.variation_specs:
            dat.extend(variation.serialize())
        return bytes(dat)


    def validate(self, transaction, validation_tool):
        return False


class ValueAssetBody(BaseAssetBody):

    def __init__(self, value_specified, time_of_origin, variation_specs):
        super().__init__(super().T_VALUE, value_specified, time_of_origin,
                variation_specs)


class ChangeAssetBody(BaseAssetBody):

    def __init__(self, value_specified, time_of_origin, variation_specs):
        super().__init__(super().T_CHANGE, value_specified, time_of_origin,
                variation_specs)


class IssuedAssetBody(BaseAssetBody):

    def __init__(self, value_specified, time_of_origin, variation_specs):
        super().__init__(super().T_ISSUED, value_specified, time_of_origin,
                variation_specs)


class CurrencySpec:

    VERSION_CURRENT = 0

    MAX_DECIMAL = 12

    O_BIT_NONE                    = 0
    O_BIT_CONDITIONS_IRREVERSIBLE = 0b0000000000000001
    O_BIT_EXPIRATION_REBASED      = 0b0000000000000010
    O_BIT_WITNESSES_REQUIRED      = 0b0000000000000100


    def __init__(self, dic=None, name=None, symbol=None, decimal=None,
            variation_specs=None,
            option_witnesses_required=None,
            option_expiration_rebased=None,
            option_conditions_irreversible=None,
            version=VERSION_CURRENT):
        self.version = version

        if dic is not None:
            name = dic['name']
        if not isinstance(name, str):
            raise TypeError('name must be str')
        string = name.encode()
        if len(string) > 0x7fff:
            raise TypeError('name is too long')
        self.name = name

        if dic is not None:
            symbol = dic['symbol']
        if not isinstance(symbol, str):
            raise TypeError('symbol must be str')
        string = symbol.encode()
        if len(string) > 0x7f:
            raise TypeError('symbol is too long')
        self.symbol = symbol

        if dic is not None:
            try:
                decimal = dic['decimal']
            except KeyError:
                decimal = 0
        if not isinstance(decimal, int):
            raise TypeError('decimal must be int')
        if decimal < 0 or decimal > CurrencySpec.MAX_DECIMAL:
            raise TypeError('decimal out of range')
        self.decimal = decimal

        if dic is None:
            self.variation_specs = variation_specs
        else:
            try:
                variation_specs = dic['variation_specs']
            except KeyError:
                variation_specs = []
            self.variation_specs = []
            for spec in variation_specs:
                condition = spec['condition']
                if not isinstance(condition, int):
                    raise TypeError('condition must be int')
                if condition < 0 or condition > 0x7f:
                    raise TypeError('condition out of range')

                type0 = spec['variation_type']
                if isinstance(type0, int) and \
                        type0 >= Variation.T_SIMPLE and \
                        type0 <= Variation.T_COMPOUND:
                    type = type0
                elif type0 == 'simple':
                    type = Variation.T_SIMPLE
                elif type0 == 'compound':
                    type = Variation.T_COMPOUND
                else:
                    raise TypeError('unknown variation type')

                rate = Fraction(spec['rate'])
                if abs(rate.numerator) > 0x7fff or rate.denominator > 0x7fff:
                    raise TypeError('rate out of range')

                rate_to_stop = Fraction(spec['rate_to_stop'])
                if rate_to_stop.numerator > 0x7fff or \
                        rate_to_stop.denominator > 0x7fff or \
                        not rate_to_stop.is_positive_or_zero():
                    raise TypeError('rate_to_stop out of range')
                if rate.is_positive_or_zero():
                    if rate_to_stop.numerator < rate_to_stop.denominator:
                        raise TypeError('rate_to_stop out of range')
                elif rate_to_stop.numerator > rate_to_stop.denominator:
                    raise TypeError('rate_to_stop out of range')

                time_unit = spec['time_unit']
                if not isinstance(time_unit, int):
                    raise TypeError('time_unit must be int')
                if time_unit <= 0 or time_unit > 0x7fffffffffffffff:
                    raise TypeError('time_unit out of range')

                expire_after = spec['expire_after']
                if not isinstance(expire_after, int):
                    raise TypeError('expire_after must be int')
                if expire_after < 0 or expire_after > 0x7fffffffffffffff:
                    raise TypeError('expire_after out of range')

                self.variation_specs.append(Variation(condition=condition,
                        type=type, rate=rate, rate_to_stop=rate_to_stop,
                        time_unit=time_unit, expire_after=expire_after))

        if len(self.variation_specs) > 0x7f:
            raise TypeError('too many variation specs')

        if dic is not None:
            try:
                option_witnesses_required = dic['option_witnesses_required']
            except KeyError:
                option_witnesses_required = False
        if not isinstance(option_witnesses_required, bool):
            raise TypeError('this option must be bool')
        self.option_witnesses_required = option_witnesses_required

        if dic is not None:
            try:
                option_expiration_rebased = dic['option_expiration_rebased']
            except KeyError:
                option_expiration_rebased = False
        if not isinstance(option_expiration_rebased, bool):
            raise TypeError('this option must be bool')
        self.option_expiration_rebased = option_expiration_rebased

        if dic is not None:
            try:
                option_conditions_irreversible \
                  = dic['option_conditions_irreversible']
            except KeyError:
                option_conditions_irreversible = True
        if not isinstance(option_conditions_irreversible, bool):
            raise TypeError('this option must be bool')
        self.option_conditions_irreversible = option_conditions_irreversible


    def __eq__(self, other):
        if isinstance(other, CurrencySpec):
            if self.name != other.name or self.symbol != other.symbol:
                return False
            if self.decimal != other.decimal:
                return False
            if len(self.variation_specs) != len(other.variation_specs):
                return False
            for i in range(len(self.variation_specs)):
                if self.variation_specs[i] != other.variation_specs[i]:
                    return False
            if self.option_witnesses_required \
                    != other.option_witnesses_required:
                return False
            if self.option_expiration_rebased \
                    != other.option_expiration_rebased:
                return False
            if self.option_conditions_irreversible \
                    != other.option_conditions_irreversible:
                return False
            return True
        else:
            return False


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, version = bbclib.get_n_byte_int(ptr, 2, data)
            ptr, size = bbclib.get_n_byte_int(ptr, 2, data)
            ptr, v = bbclib.get_n_bytes(ptr, size, data)
            name = v.decode()
            ptr, size = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, v = bbclib.get_n_bytes(ptr, size, data)
            symbol = v.decode()
            ptr, decimal = bbclib.get_n_byte_int(ptr, 1, data)
            ptr, count = bbclib.get_n_byte_int(ptr, 1, data)
            variation_specs = []
            for i in range(count):
                ptr, variation = Variation.from_serialized_data(ptr, data)
                variation_specs.append(variation)
            ptr, v = bbclib.get_n_byte_int(ptr, 2, data)
            option_witnesses_required = \
                    v & CurrencySpec.O_BIT_WITNESSES_REQUIRED != 0
            option_expiration_rebased = \
                    v & CurrencySpec.O_BIT_EXPIRATION_REBASED != 0
            option_conditions_irreversible = \
                    v & CurrencySpec.O_BIT_CONDITIONS_IRREVERSIBLE != 0
        except:
            raise
        return ptr, CurrencySpec(name=name, symbol=symbol, decimal=decimal,
                variation_specs=variation_specs,
                option_witnesses_required=option_witnesses_required,
                option_expiration_rebased=option_expiration_rebased,
                option_conditions_irreversible=option_conditions_irreversible,
                version=version)


    def serialize(self):
        dat = bytearray(bbclib.to_2byte(self.version))
        string = self.name.encode()
        dat.extend(bbclib.to_2byte(len(string)))
        dat.extend(string)
        string = self.symbol.encode()
        dat.extend(bbclib.to_1byte(len(string)))
        dat.extend(string)
        dat.extend(bbclib.to_1byte(self.decimal))

        dat.extend(bbclib.to_1byte(len(self.variation_specs)))
        for variation in self.variation_specs:
            dat.extend(variation.serialize())

        options = CurrencySpec.O_BIT_NONE
        if self.option_witnesses_required:
            options |= CurrencySpec.O_BIT_WITNESSES_REQUIRED
        if self.option_expiration_rebased:
            options |= CurrencySpec.O_BIT_EXPIRATION_REBASED
        if self.option_conditions_irreversible:
            options |= CurrencySpec.O_BIT_CONDITIONS_IRREVERSIBLE
        dat.extend(bbclib.to_2byte(options))
        return bytes(dat)


class ConditionAssetBody:

    def __init__(self, condition=0):
        self.condition = condition


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, condition = bbclib.get_n_byte_int(ptr, 1, data)
        except:
            raise
        return ptr, ConditionAssetBody(condition)


    def serialize(self):
        dat = bytearray(bbclib.to_1byte(self.condition))
        return bytes(dat)


class CurrencySpecAssetBody:

    def __init__(self, currency_spec):
        self.currency_spec = currency_spec


    @staticmethod
    def from_serialized_data(ptr, data):
        try:
            ptr, currency_spec = CurrencySpec.from_serialized_data(ptr, data)
        except:
            raise
        return ptr, CurrencySpecAssetBody(currency_spec)


    def serialize(self):
        dat = bytearray(self.currency_spec.serialize())
        return bytes(dat)


class Store:

    IDX_CONDITION     = 0
    IDX_CURRENCY_SPEC = 1

    SEED_CONDITION     = '.condition'
    SEED_CURRENCY_SPEC = '.currency_spec'


    def __init__(self, domain_id, mint_id, app):
        self.domain_id = domain_id
        self.mint_id = mint_id
        self.app = app
        self.db_online = True
        self.db = app_support_lib.Database()
        self.db.setup_db(domain_id, NAME_OF_DB)
        self.db.create_table_in_db(domain_id, NAME_OF_DB,
                'token_utxo_table',
                token_utxo_table_definition,
                indices=[0, 1, 2])
        self.db.create_table_in_db(domain_id, NAME_OF_DB,
                'token_tx_id_table',
                token_tx_id_table_definition,
                primary_key=0, indices=[1])
        self.store_ids = (
            self.get_store_id(Store.SEED_CONDITION),
            self.get_store_id(Store.SEED_CURRENCY_SPEC)
        )


    def delete_utxo(self, tx_id, idx):
        if self.db_online is False:
            return None
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('update token_utxo_table set state=?, last_modified=? where '
             'tx_id=? and event_idx=?'),
            ST_TAKEN,
            int(time.time()),
            tx_id,
            idx
        )


    def get_balance_of(self, user_id, eval_time=None):
        rows = self.read_utxo_list(user_id)
        if len(rows) == 0:
            return 0

        if eval_time is None:
            eval_time = int(time.time())

        balance = 0
        condition = self.get_condition()
        for row in rows:
            _, body = BaseAssetBody.from_serialized_data(0,
                    row[IDX_ASSET_BODY])
            balance += body.get_effective_value(eval_time, condition)
        return balance


    def get_condition(self):
        _, body = ConditionAssetBody.from_serialized_data(0,
                self.get_mint_data(Store.IDX_CONDITION))
        return body.condition


    def get_currency_spec(self):
        _, body = CurrencySpecAssetBody.from_serialized_data(0,
                self.get_mint_data(Store.IDX_CURRENCY_SPEC))
        return body.currency_spec


    def get_mint_data(self, index):
        store_id = self.store_ids[index]

        self.app.search_transaction_with_condition(
                asset_group_id=self.mint_id, user_id=store_id)
        res = self.app.callback.synchronize()
        if res[KeyType.status] < ESUCCESS:
            raise ValueError('not found')
        tx = bbclib.BBcTransaction(deserialize=res[KeyType.transactions][0])
        return tx.events[0].asset.asset_body


    def get_sorted_utxo_list(self, user_id, eval_time=None):
        rows = self.read_utxo_list(user_id)
        if len(rows) == 0:
            return []

        if eval_time is None:
            eval_time = int(time.time())

        tuples = []
        condition = self.get_condition()
        for row in rows:
            _, body = BaseAssetBody.from_serialized_data(0,
                    row[IDX_ASSET_BODY])
            value, gain = body.get_expected_loss_or_gain(eval_time, condition)
            tuples.append((value, gain, row))
        tuples = sorted(tuples, key=lambda t: t[0])
        return sorted(tuples, key=lambda t: t[1])


    def get_store_id(self, seed):
        dat = bytearray(self.mint_id)
        dat.extend(seed.encode())
        return hashlib.sha256(bytes()).digest()


    def get_tx(self, tx_id):
        self.app.search_transaction(tx_id)
        res = self.app.callback.synchronize()
        if res[KeyType.status] < ESUCCESS:
            raise ValueError('not found')
        tx = bbclib.recover_transaction_object_from_rawdata(
                res[KeyType.transaction_data])
        return tx


    def insert(self, tx, user_id, idPublickeyMap):
        if idPublickeyMap.verify_signers(tx, self.mint_id, user_id) == False:
            raise RuntimeError('signers not verified')

        self.push_tx(tx.transaction_id, tx)
        ret = self.app.insert_transaction(tx)
        assert ret
        res = self.app.callback.synchronize()
        if res[KeyType.status] < ESUCCESS:
            raise RuntimeError(res[KeyType.reason].decode())


    def inserted(self, tx_id):
        tx = self.take_tx(tx_id)
        if tx is None:
            return

        # FIXME: check validity
        for i, event in enumerate(tx.events):
            if event.asset_group_id == self.mint_id and \
              event.asset.user_id not in self.store_ids:
                _, body = BaseAssetBody.from_serialized_data(0,
                        event.asset.asset_body)
                self.write_utxo(event.asset.user_id,
                        tx.transaction_id, i, event.asset.asset_body, True)

        for ref in tx.references:
            if ref.asset_group_id == self.mint_id:
                self.delete_utxo(ref.transaction_id, ref.event_index_in_ref)


    def push_tx(self, tx_id, tx):
        if self.db_online is False:
            return
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'insert into token_tx_id_table values (?, ?)',
            tx_id,
            tx.serialize()
        )


    def read_utxo_list(self, user_id):
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select * from token_utxo_table where '
             'mint_id=? and user_id=? and state=?'),
            self.mint_id,
            user_id,
            ST_FREE
        )


    def reserve_utxo(self, tx_id, idx):
        if self.db_online is False:
            return None
        return self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('update token_utxo_table set state=?, last_modified=? where '
             'tx_id=? and event_idx=?'),
            ST_RESERVED,
            int(time.time()),
            tx_id,
            idx
        )


    def reserve_referred_utxos(self, tx):
        for ref in tx.references:
            if ref.asset_group_id == self.mint_id:
                self.reserve_utxo(ref.transaction_id, ref.event_index_in_ref)


    '''
    mainly for testing purposes.
    '''
    def set_db_online(self, is_online=True):
        self.db_online = is_online


    def set_condition(self, condition, update=False, keypair=None,
            idPublickeyMap=None):
        return self.set_mint_data(Store.IDX_CONDITION,
                ConditionAssetBody(condition).serialize(), update, keypair,
                idPublickeyMap)


    def set_currency_spec(self, currency_spec, update=False, keypair=None,
            idPublickeyMap=None):
        return self.set_mint_data(Store.IDX_CURRENCY_SPEC,
                CurrencySpecAssetBody(currency_spec).serialize(), update,
                keypair, idPublickeyMap)


    def set_mint_data(self, index, asset_body, update=False, keypair=None,
            idPublickeyMap=None):
        store_id = self.store_ids[index]

        if update:
            self.app.search_transaction_with_condition(
                    asset_group_id=self.mint_id, user_id=store_id)
            res = self.app.callback.synchronize()
            if res[KeyType.status] >= ESUCCESS:
                reftx = bbclib.BBcTransaction(
                        deserialize=res[KeyType.transactions][0])
        else:
            reftx = None

        tx = bbclib.make_transaction_for_base_asset(
                asset_group_id=self.mint_id, event_num=1)
        tx.events[0].asset.add(user_id=store_id, asset_body=asset_body)
        tx.events[0].add(mandatory_approver=self.mint_id)
        if reftx is None:
            tx.add(witness=bbclib.BBcWitness())
            tx.witness.add_witness(self.mint_id)
        else:
            bbclib.add_reference_to_transaction(self.mint_id, tx, reftx, 0)

        if keypair is None:
            return tx

        return self.sign_and_insert(tx, self.mint_id, keypair, idPublickeyMap)


    def sign(self, transaction, user_id, keypair):
        sig = transaction.sign(key_type=bbclib.KeyType.ECDSA_SECP256k1,
                private_key=keypair.private_key,
                public_key=keypair.public_key)
        transaction.add_signature(user_id=user_id, signature=sig)
        return sig


    def sign_and_insert(self, transaction, user_id, keypair, idPublickeyMap):
        self.sign(transaction, user_id, keypair)
        transaction.digest()
        self.insert(transaction, user_id, idPublickeyMap)
        return transaction


    def take_tx(self, tx_id):
        if self.db_online is False:
            return None
        rows = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select tx from token_tx_id_table where tx_id=?',
            tx_id
        )
        if len(rows) <= 0:
            return None
        tx = bbclib.BBcTransaction()
        tx.deserialize(rows[0][0])
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'delete from token_tx_id_table where tx_id=?',
            tx_id
        )
        return tx


    def write_utxo(self, user_id, tx_id, idx, asset_body, is_single):
        if self.db_online is False:
            return
        self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'insert into token_utxo_table values (?, ?, ?, ?, ?, ?, ?, ?)',
            self.mint_id,
            user_id,
            tx_id,
            idx,
            asset_body,
            is_single,
            ST_FREE,
            int(time.time())
        )


class BBcMint:

    """
    Domain and mint user (both asset group and user) ids must have been
    registered to the core prior to creating this object.
    """
    def __init__(self, domain_id, mint_id, user_id, idPublickeyMap,
                    port=DEFAULT_CORE_PORT, logname="-", loglevel="none"):
        self.logger = logger.get_logger(key="token_lib", level=loglevel,
                                        logname=logname) # FIXME: use logger
        self.condition = 0
        self.domain_id = domain_id
        self.mint_id = mint_id
        self.user_id = user_id
        self.idPublickeyMap = idPublickeyMap
        self.app = bbc_app.BBcAppClient(port=DEFAULT_CORE_PORT,
                                        loglevel=loglevel)
        self.app.set_user_id(user_id)
        self.app.set_domain_id(domain_id)
        self.app.set_callback(MintCallback(logger, self))
        ret = self.app.register_to_core()
        assert ret

        self.store = Store(self.domain_id, self.mint_id, self.app)
        self.app.request_insert_completion_notification(self.mint_id)


    def get_balance_of(self, user_id, eval_time=None):
        if eval_time is None:
            eval_time = int(time.time())
        return self.store.get_balance_of(user_id, eval_time)


    def get_condition(self):
        self.condition = self.store.get_condition()
        return self.condition


    def get_currency_spec(self):
        self.currency_spec = self.store.get_currency_spec()
        return self.currency_spec


    def get_total_supply(self, eval_time=None):
        if eval_time is None:
            eval_time = int(time.time())
        return # FIXME: implement this


    def issue(self, to_user_id, amount, time_of_origin=None, keypair=None):
        if self.user_id != self.mint_id:
            raise RuntimeError('issuer must be the mint')

        tx = bbclib.make_transaction_for_base_asset(
                asset_group_id=self.mint_id, event_num=1)
        if time_of_origin is None:
            time_of_origin = tx.timestamp
        tx.events[0].asset.add(user_id=to_user_id, asset_body=IssuedAssetBody(
                amount, time_of_origin,
                self.currency_spec.variation_specs).serialize())
        tx.events[0].add(mandatory_approver=self.mint_id)
        tx.events[0].add(mandatory_approver=to_user_id)
        tx.add(witness=bbclib.BBcWitness())
        tx.witness.add_witness(self.mint_id)

        if keypair is None:
            return tx

        return self.store.sign_and_insert(tx, self.mint_id, keypair,
                self.idPublickeyMap)


    def make_event(self, ref_indice, user_id, body):
        event = bbclib.BBcEvent(asset_group_id=self.mint_id)
        for i in ref_indice:
            event.add(reference_index=i)
        event.add(mandatory_approver=self.mint_id)
        event.add(mandatory_approver=user_id)
        event.add(asset=bbclib.BBcAsset())
        event.asset.add(user_id=user_id, asset_body=body.serialize())
        return event


#    def refund(self, from_user_id, to_user_id, amount):


    def set_condition(self, condition, update=False, keypair=None):
        self.condition = condition
        return self.store.set_condition(condition, update, keypair,
                self.idPublickeyMap)


    def set_currency_spec(self, currency_spec, update=False, keypair=None):
        self.currency_spec = currency_spec
        return self.store.set_currency_spec(currency_spec, update, keypair,
                self.idPublickeyMap)


    def set_keypair(self, keypair):
        self.app.callback.set_keypair(keypair)


    def sign_and_insert(self, transaction, user_id, keypair):
        return self.store.sign_and_insert(transaction, user_id, keypair,
                self.idPublickeyMap)


#    def swap(self, counter_mint, this_user_id, that_user_id,
#                this_amount, that_amount):



    def transfer(self, from_user_id, to_user_id, amount, keypair_from=None,
            keypair_mint=None):
        tx = bbclib.BBcTransaction()
        sorted_tuples = self.store.get_sorted_utxo_list(from_user_id,
                tx.timestamp)
        num_refs = 0
        value = 0
        for t in sorted_tuples:
            num_refs += 1
            value += t[0]
            if value >= amount:
                break
        if value < amount:
            raise ValueError("not enough fund")

        spec_tuples = []
        for i in range(num_refs):
            ref_tx = self.store.get_tx(sorted_tuples[i][2][IDX_TX_ID])
            ref = bbclib.BBcReference(asset_group_id=self.mint_id,
                    transaction=tx,
                    ref_transaction=ref_tx,
                    event_index_in_ref=sorted_tuples[i][2][IDX_EVENT_IDX])
            tx.add(reference=ref)
            _, body = BaseAssetBody.from_serialized_data(0,
                    ref_tx.events[ref.event_index_in_ref].asset.asset_body)
            found = False
            for t in spec_tuples:
                if body.is_same_spec(t[2], t[3]):
                    found = True
                    t[0] += sorted_tuples[i][0]
                    t[1] += body.value_specified
                    t[4].append(i)
                    break
            if found == False:
                spec_tuples.append([
                    sorted_tuples[i][0],
                    body.value_specified,
                    body.time_of_origin,
                    body.variation_specs,
                    [i]
                ])

        for i, t in enumerate(spec_tuples):
            amount -= t[0]
            if amount >= 0:
                body = BaseAssetBody(BaseAssetBody.T_VALUE, t[1], t[2], t[3])
                tx.add(event=self.make_event(t[4], to_user_id, body))
            else:
                idx = i
                break

        if amount < 0:
            t = spec_tuples[idx]
            v = (t[1] * (t[0] + amount)) // t[0]

            body = BaseAssetBody(BaseAssetBody.T_VALUE, v, t[2], t[3])
            while body.get_effective_value(tx.timestamp,
                    self.store.get_condition()) < t[0] + amount and \
                    body.value_specified < t[1]:
                body.value_specified += 1
            v = body.value_specified
            tx.add(event=self.make_event(t[4], to_user_id, body))

            body = BaseAssetBody(BaseAssetBody.T_CHANGE, t[1] - v, t[2], t[3])
            tx.add(event=self.make_event(t[4], from_user_id, body))

            for i in range(idx + 1, len(spec_tuples)):
                t = spec_tuples[i]
                body = BaseAssetBody(BaseAssetBody.T_CHANGE, t[1], t[2], t[3])
                tx.add(event=self.make_event(t[4], from_user_id, body))

        if keypair_from is None:
            return tx

        if keypair_mint is None:
            self.app.gather_signatures(tx, destinations=[self.mint_id])
            res = self.app.callback.synchronize()
            if res[KeyType.status] < ESUCCESS:
                raise RuntimeError(res[KeyType.reason].decode())
            result = res[KeyType.result]
            tx.add_signature(self.mint_id, signature=result[2])
            return self.store.sign_and_insert(tx, from_user_id, keypair_from,
                    self.idPublickeyMap)

        self.store.sign(tx, from_user_id, keypair_from)

        return self.store.sign_and_insert(tx, self.mint_id, keypair_mint,
                self.idPublickeyMap)


class MintCallback(bbc_app.Callback):

    def __init__(self, logger, mint):
        super().__init__(logger)
        self.mint = mint
        self.keypair = None


    def proc_cmd_sign_request(self, dat):
        source_user_id = dat[KeyType.source_user_id]

        if self.keypair is None:
            self.mint.app.sendback_denial_of_sign(source_user_id,
                    'keypair is unset')

        tx = bbclib.BBcTransaction()
        tx.deserialize(dat[KeyType.transaction_data])

        # FIXME: check validity

        sig = self.mint.store.sign(tx, self.mint.user_id, self.keypair)
        tx.digest()

        self.mint.store.reserve_referred_utxos(tx)
        self.mint.store.push_tx(tx.transaction_id, tx)
        self.mint.app.sendback_signature(source_user_id, tx.transaction_id,
                -1, sig)


    def proc_notify_inserted(self, dat):
        self.mint.store.inserted(dat[KeyType.transaction_id])


    def set_keypair(self, keypair):
        self.keypair = keypair


# end of token_lib.py
