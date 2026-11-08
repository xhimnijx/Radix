//! Decode-only Postcard adapter with explicit, fail-closed traversal budgets.
//!
//! This preserves Postcard's wire format. It limits the total number of visited
//! sequence/map elements and the aggregate length of decoded string/byte values.
//! These are element/decoded-byte proxies, **not** a generic exact heap-byte
//! bound: inline type sizes, allocator growth, custom `Deserialize` behavior,
//! and allocations performed before a callback cannot be inferred generically.
//!
//! Known sequence lengths are charged before the visitor is invoked, then the
//! wrapped access object hides its size hint so standard `Vec` visitors do not
//! reserve from an attacker-controlled count. Unknown lengths are charged in a
//! `DeserializeSeed` immediately before each actual element is deserialized.

use serde::de::Error as _;
use serde::de::{
    self, Deserialize, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};

macro_rules! delegate {
    ($method:ident $(, $arg:ident : $arg_ty:ty)*) => {
        fn $method<V>(self, $($arg: $arg_ty,)* visitor: V) -> Result<V::Value, Self::Error>
        where
            V: Visitor<'de>,
        {
            let Self { inner, budget } = self;
            inner.$method($($arg,)* BudgetVisitor { inner: visitor, budget })
        }
    };
}

macro_rules! forward_visit {
    ($method:ident, $value_ty:ty) => {
        fn $method<E>(self, value: $value_ty) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.inner.$method(value)
        }
    };
}

/// Source-derived maximum aggregate sequence/tuple/struct traversal count for a
/// proof payload of `payload_len` bytes.
///
/// One Postcard element occupies at least one byte, and a decoded value cannot
/// exceed a schema-bounded multiple of its encoding. A fixed ceiling previously
/// broke (a 249 kB proof exceeded it) because the constant was hand-derived and
/// never re-derived when the proof schema grew. Deriving it from the input keeps
/// decode work linear in the input while still refusing declared-length
/// amplification: a crafted 1 kB payload can claim at most ~8 k elements.
pub const fn sequence_element_limit(payload_len: usize) -> usize {
    payload_len.saturating_mul(8).saturating_add(4_096)
}

/// Explicit limits required for each bounded decode. There is intentionally no
/// unbounded/default configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum aggregate sequence elements, including tuple/struct fields and
    /// map keys and values.
    pub sequence_elements: usize,
    /// Maximum aggregate bytes in decoded strings and byte buffers.
    pub decoded_bytes: usize,
}

/// Mutable accounting state for one decode operation.
#[derive(Debug)]
pub struct Budget {
    limits: Limits,
    sequence_elements: usize,
    decoded_bytes: usize,
}

impl Budget {
    /// Start a fresh budget. Each input should use its own budget instance.
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            sequence_elements: 0,
            decoded_bytes: 0,
        }
    }

    /// Number of sequence/map elements charged so far.
    pub const fn sequence_elements_used(&self) -> usize {
        self.sequence_elements
    }

    /// Number of string/byte payload bytes charged so far.
    pub const fn decoded_bytes_used(&self) -> usize {
        self.decoded_bytes
    }

    fn charge_elements<E: de::Error>(&mut self, count: usize) -> Result<(), E> {
        let next = self
            .sequence_elements
            .checked_add(count)
            .ok_or_else(|| E::custom("bounded postcard sequence-element counter overflow"))?;
        if next > self.limits.sequence_elements {
            return Err(E::custom(
                "bounded postcard sequence-element limit exceeded",
            ));
        }
        self.sequence_elements = next;
        Ok(())
    }

    fn charge_bytes<E: de::Error>(&mut self, count: usize) -> Result<(), E> {
        let next = self
            .decoded_bytes
            .checked_add(count)
            .ok_or_else(|| E::custom("bounded postcard decoded-byte counter overflow"))?;
        if next > self.limits.decoded_bytes {
            return Err(E::custom("bounded postcard decoded-byte limit exceeded"));
        }
        self.decoded_bytes = next;
        Ok(())
    }
}

/// Deserialize from Postcard bytes while enforcing both supplied budgets.
///
/// Like `postcard::from_bytes`, this does not reject an unused input suffix;
/// callers that require canonical/no-trailing-byte encodings must retain their
/// existing exact reserialization check.
pub fn from_bytes<'de, T>(bytes: &'de [u8], budget: &mut Budget) -> postcard::Result<T>
where
    T: Deserialize<'de>,
{
    let mut inner = postcard::Deserializer::from_bytes(bytes);
    T::deserialize(BudgetedDeserializer {
        inner: &mut inner,
        budget,
    })
}

/// Decode one of the current proof graphs with a traversal ceiling derived from
/// the input length. The decoded-byte allowance is bounded by the input slice;
/// this is not a heap/RSS cap. Callers must still enforce their profile's wire
/// limit before calling this helper (as the envelope decoders do).
pub fn from_proof_bytes<'de, T>(bytes: &'de [u8]) -> postcard::Result<T>
where
    T: Deserialize<'de>,
{
    let mut budget = Budget::new(Limits {
        sequence_elements: sequence_element_limit(bytes.len()),
        decoded_bytes: bytes.len(),
    });
    from_bytes(bytes, &mut budget)
}

struct BudgetedDeserializer<'budget, D> {
    inner: D,
    budget: &'budget mut Budget,
}

impl<'de, 'budget, D> de::Deserializer<'de> for BudgetedDeserializer<'budget, D>
where
    D: de::Deserializer<'de>,
{
    type Error = D::Error;

    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }

    delegate!(deserialize_any);
    delegate!(deserialize_bool);
    delegate!(deserialize_i8);
    delegate!(deserialize_i16);
    delegate!(deserialize_i32);
    delegate!(deserialize_i64);
    delegate!(deserialize_i128);
    delegate!(deserialize_u8);
    delegate!(deserialize_u16);
    delegate!(deserialize_u32);
    delegate!(deserialize_u64);
    delegate!(deserialize_u128);
    delegate!(deserialize_f32);
    delegate!(deserialize_f64);
    delegate!(deserialize_char);
    delegate!(deserialize_str);
    delegate!(deserialize_string);
    delegate!(deserialize_bytes);
    delegate!(deserialize_byte_buf);
    delegate!(deserialize_option);
    delegate!(deserialize_unit);
    delegate!(deserialize_unit_struct, name: &'static str);
    delegate!(deserialize_newtype_struct, name: &'static str);
    delegate!(deserialize_seq);
    delegate!(deserialize_tuple, len: usize);
    delegate!(deserialize_tuple_struct, name: &'static str, len: usize);
    delegate!(deserialize_map);
    delegate!(deserialize_struct, name: &'static str, fields: &'static [&'static str]);
    delegate!(deserialize_enum, name: &'static str, variants: &'static [&'static str]);
    delegate!(deserialize_identifier);
    delegate!(deserialize_ignored_any);
}

struct BudgetVisitor<'budget, V> {
    inner: V,
    budget: &'budget mut Budget,
}

impl<'de, 'budget, V> Visitor<'de> for BudgetVisitor<'budget, V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.expecting(formatter)
    }

    forward_visit!(visit_bool, bool);
    forward_visit!(visit_i8, i8);
    forward_visit!(visit_i16, i16);
    forward_visit!(visit_i32, i32);
    forward_visit!(visit_i64, i64);
    forward_visit!(visit_i128, i128);
    forward_visit!(visit_u8, u8);
    forward_visit!(visit_u16, u16);
    forward_visit!(visit_u32, u32);
    forward_visit!(visit_u64, u64);
    forward_visit!(visit_u128, u128);
    forward_visit!(visit_f32, f32);
    forward_visit!(visit_f64, f64);

    fn visit_char<E>(self, value: char) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        budget.charge_bytes::<E>(value.len_utf8())?;
        inner.visit_char(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_str(value)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_borrowed_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        // For Postcard's public Deserializer, owned String visitors receive
        // visit_str first, so this check is defensive for custom visitors.
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_string(value)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_bytes(value)
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_borrowed_bytes(value)
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let Self { inner, budget } = self;
        // Postcard calls visit_bytes for deserialize_byte_buf; this covers
        // custom visitors that hand over an already-owned buffer.
        budget.charge_bytes::<E>(value.len())?;
        inner.visit_byte_buf(value)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.inner.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let Self { inner, budget } = self;
        inner.visit_some(BudgetedDeserializer {
            inner: deserializer,
            budget,
        })
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.inner.visit_unit()
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let Self { inner, budget } = self;
        inner.visit_newtype_struct(BudgetedDeserializer {
            inner: deserializer,
            budget,
        })
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let Self { inner, budget } = self;
        let known_len = seq.size_hint();
        if let Some(len) = known_len {
            budget.charge_elements::<A::Error>(len)?;
        }
        inner.visit_seq(BudgetSeqAccess {
            inner: seq,
            budget,
            precharged: known_len.is_some(),
        })
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let Self { inner, budget } = self;
        let known_len = map.size_hint();
        if let Some(len) = known_len {
            let elements = len
                .checked_mul(2)
                .ok_or_else(|| A::Error::custom("bounded postcard map-element count overflow"))?;
            budget.charge_elements::<A::Error>(elements)?;
        }
        inner.visit_map(BudgetMapAccess {
            inner: map,
            budget,
            precharged: known_len.is_some(),
        })
    }

    fn visit_enum<A>(self, access: A) -> Result<Self::Value, A::Error>
    where
        A: EnumAccess<'de>,
    {
        let Self { inner, budget } = self;
        inner.visit_enum(BudgetEnumAccess {
            inner: access,
            budget,
        })
    }
}

struct BudgetSeed<'budget, S> {
    inner: S,
    budget: &'budget mut Budget,
    charge_element: bool,
}

impl<'de, 'budget, S> DeserializeSeed<'de> for BudgetSeed<'budget, S>
where
    S: DeserializeSeed<'de>,
{
    type Value = S::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let Self {
            inner,
            budget,
            charge_element,
        } = self;
        if charge_element {
            budget.charge_elements::<D::Error>(1)?;
        }
        inner.deserialize(BudgetedDeserializer {
            inner: deserializer,
            budget,
        })
    }
}

struct BudgetSeqAccess<'budget, A> {
    inner: A,
    budget: &'budget mut Budget,
    precharged: bool,
}

impl<'de, 'budget, A> SeqAccess<'de> for BudgetSeqAccess<'budget, A>
where
    A: SeqAccess<'de>,
{
    type Error = A::Error;

    fn next_element_seed<S>(&mut self, seed: S) -> Result<Option<S::Value>, Self::Error>
    where
        S: DeserializeSeed<'de>,
    {
        let exhausted = self.inner.size_hint() == Some(0);
        self.inner.next_element_seed(BudgetSeed {
            inner: seed,
            budget: self.budget,
            charge_element: !self.precharged && !exhausted,
        })
    }

    // Do not let Vec or other collection visitors preallocate from the encoded
    // count. Known counts have already been charged; unknown counts are charged
    // before the next element's seed runs.
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

struct BudgetMapAccess<'budget, A> {
    inner: A,
    budget: &'budget mut Budget,
    precharged: bool,
}

impl<'de, 'budget, A> MapAccess<'de> for BudgetMapAccess<'budget, A>
where
    A: MapAccess<'de>,
{
    type Error = A::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        let exhausted = self.inner.size_hint() == Some(0);
        self.inner.next_key_seed(BudgetSeed {
            inner: seed,
            budget: self.budget,
            charge_element: !self.precharged && !exhausted,
        })
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        self.inner.next_value_seed(BudgetSeed {
            inner: seed,
            budget: self.budget,
            charge_element: !self.precharged,
        })
    }

    fn size_hint(&self) -> Option<usize> {
        None
    }
}

struct BudgetEnumAccess<'budget, A> {
    inner: A,
    budget: &'budget mut Budget,
}

impl<'de, 'budget, A> EnumAccess<'de> for BudgetEnumAccess<'budget, A>
where
    A: EnumAccess<'de>,
{
    type Error = A::Error;
    type Variant = BudgetVariantAccess<'budget, A::Variant>;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let Self { inner, budget } = self;
        let (variant, access) = inner.variant_seed(BudgetSeed {
            inner: seed,
            budget,
            charge_element: false,
        })?;
        Ok((
            variant,
            BudgetVariantAccess {
                inner: access,
                budget,
            },
        ))
    }
}

struct BudgetVariantAccess<'budget, A> {
    inner: A,
    budget: &'budget mut Budget,
}

impl<'de, 'budget, A> VariantAccess<'de> for BudgetVariantAccess<'budget, A>
where
    A: VariantAccess<'de>,
{
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }

    fn newtype_variant_seed<S>(self, seed: S) -> Result<S::Value, Self::Error>
    where
        S: DeserializeSeed<'de>,
    {
        self.inner.newtype_variant_seed(BudgetSeed {
            inner: seed,
            budget: self.budget,
            charge_element: false,
        })
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.tuple_variant(
            len,
            BudgetVisitor {
                inner: visitor,
                budget: self.budget,
            },
        )
    }

    fn struct_variant<V>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.struct_variant(
            fields,
            BudgetVisitor {
                inner: visitor,
                budget: self.budget,
            },
        )
    }
}
