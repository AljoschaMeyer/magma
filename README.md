# Magma

A specification and protocol for representing and transmitting values that changed over time in an untrusted decentralized setting.

**Status: work in progress. The ideas are mostly there, but the write-up is a mess.**

**[https://aljoscha-meyer.de/magma](https://aljoscha-meyer.de/magma) is more up-to-date, ignore this for now**

Magma revolves around two concepts: cryptographically secure hashes and monoids. A [cryptographically secure hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function) maps values to short digest which are unique with a very high probability, and even a malicious act there trying to find values that hash to non-unique digest cannot do better than that probability dictates.

A [monoid](https://en.wikipedia.org/wiki/Monoid) is a set of values with a binary operation that is associative and has a neutral element. Monoids can be used to represent values changing over time. Consider for example a variable holding an integer. Rather than representing its evolution over time by keeping a sequence of the values the variable held, you can keep a sequence of the differences between the values. An integer can not only be interpreted as a specific value, but also as an operation that can be applied to a different value by adding it. Even when thinking of an integer as a value, you can interpreted as the operation taking the neutral element (zero) to the desired value.

Magma explores the interplay between these two concepts: monoidal values referring to past values by their hashes. When a datum contains the hash of another datum, this implies that the latter datum must have already existed when the prior datum was created. Such data form a [directed acyclic graph](https://en.wikipedia.org/wiki/Directed_acyclic_graph). Because hashes cannot be forged, any datum authenticates all data it transitively refers to.

This can be used when storing the evolution of a monoidal value over time in a distributed fashion: the value of a variable at a specific point in time can be represented as the monoid value representing the change from the previous value, and the hash of the previous value of the variable. Suppose a peer in the system knows the value at time `t39` and then obtains the hash of the value at time `t42` from a trusted source. This peer can then request the value-hash pairs for time points `t42` to `t40` from any untrusted source, and verify that the values have not been tampered with using the hashes.

The main motivation for such a system is one of preserving bandwidth. The value at time `t42` might be a very large object, but the series of changes leading from the value at time `t39` to the value at time `t42` might be very small. Magma provides a generic framework for representing values and transmitting them in settings where this assumption is reasonable.

## Developing the Protocol

In this section we develop the core ideas of the protocol. We begin by giving a bunch of definitions:

Let `(T, +_T, 0_T)` be a monoid, and let `value_sequence = [v_1, v_2, ..., v_k]` be a sequence of values of type `T`. We then call `predecessor_delta_sequence = [d_1, d_2, ..., d_k]` the corresponding sequence such that `d_1 +_T d_2 +_T ... +_T d_i = v_i` for all `1 <= i <= k`.

Let `h` be a secure hash function. An `Event` consists of a `predecessor_delta_id` which is the digest of some value of type `T`, and the `predecessor_event_id` which is either the digest of an `Event` or the digest zero. For a `value_sequence = [v_1, v_2, ..., v_k]` with `predecessor_delta_sequence = [d_1, d_2, ..., d_k]`, the corresponding `event_sequence = [e_1, e_2, ..., e_k]` is recursively defined as `e_1 = Event { predecessor_delta_id = h(d_1), predecessor_event_id = 0 }`, `e_i = Event { predecessor_delta_id = h(d_i), predecessor_event_id = h(e_{i-1}) }`.

Now suppose `A` is a peer that knows the values `v_i` and `e_i` for some `1 <= i < k`, and `h(e_j)` for some `i < j <= k`. `B` is a peer that knows the full `predecessor_delta_sequence`, `event_sequence`, and can efficiently map the hash of any known event to the corresponding event value. `A` wants to obtain `v_j` by communicating with `B`, but does not trust `B`. This can be achieved through the following sequence of events:

- `A` sends: "I would like to obtain the value corresponding to `h(e_j)`, my current level of knowledge is `h(e_i)`"
- `A` initializes the local variable `accumulator` to `v_i`
- `B` looks up `e_j` and then recursively looks up the predecessor events until it finds `e_i`; if it does not reach `e_i` this way, it politely informs `A` that it cannot be of service
- `B` sends `e_j`, then `e_{l-1}`, and so on, up to `e_{i+1}`
- `B` then sends `d_{i+1}`, then `d_{i+2}`, and so on, up to `d_j`
- when `A` receives `e_j`, it verifies that hashing that value does indeed yield `h(e_j)`
- next, when `A` receives any of the successive events, it verifies that hashing it yields the `predecessor_event_id` of the previously received event
- next, when `A` receives `e_{i+1}`, it also verifies that its `predecessor_event_id` is equal to `h(e_i)`
- next, when `A` receives some `d_l`, it verifies that hashing it yields the `predecessor_delta_id` of `e_l`, and then updates `accumulator` to `accumulator +_T d_l`

This exchange enables `A` to detect if `B` tries to send invalid data. Because events include hashes of monoid values rather than the values themselves, the number of bytes transferred in the initial phase of `B`'s transmission does not depend on the size of the values.

There is however still a denial of service attack `B` can perform: rather than sending `d_{l+1}`, it can send an arbitrarily long string of garbage. `A` has to patiently compute its hash, not knowing that the input to the hash function will never end.

To protect against this, we add a third datum to each event `e_i`: `predecessor_delta_size`, the number of bytes in the transport encoding of `d_i`. This information allows `A` to drop the connection when a value transmitted by `B` exceeds the size promised in its corresponding event. This mechanism can only work if the `predecessor_delta_size` of all events in circulation is accurate, for that reason `A` has to reject a potential `d_l` if it is too small as well, even if the hash is correct.

This protocol exhibits linear complexities: `B` sends `j - i` many events, and `A` has to store that many events in memory in order to check the integrity of the following delta sequence. We can employ a [binary anti-monotone linking scheme](https://aljoscha-meyer.de/linkingschemes) to reduce these complexities to `O(log(j))`. The remainder of this text assumes familiarity with the concepts and terminology introduced in that link. In particular, we use the function [`ls3`](https://aljoscha-meyer.de/linkingschemes#lsthree).

We extend the definition of an event `e_i` to include the following data:

- `sequence_number`, a 64-bit integer set to `i` (magma does not support sequences of length greater than `2^64 - 1`, and sequence numbers start at `1`)
- `skip_delta_id`, the monoid value `s_i` such that `v_{bs3(i)} +_T s_i = v_i`, or `v1` if `i = 1`
- `skip_event_id`, the digest `h(e_{bs3(i)})`, or `0` if `i = 1`
- `skip_delta_size`, the number of bytes in the transport encoding of `s_i`

Intuitively, `B` can now send data along the shortest path between `e_j` and `e_i`, rather than going through all the predecessor links. More precisely, consider again the situation where

- `A` is a peer that knows the values `v_i` and `e_i` for some `1 <= i < k`, and `h(e_j)` for some `i < j <= k`.
- `B` is a peer that knows the full `predecessor_delta_sequence`, `event_sequence`, and can efficiently map the hash of any known event to the corresponding event value.
- `A` wants to obtain `v_j` by communicating with `B`, but does not trust `B`.

Using the extended definition of an event, this can be done with fewer messages and state:

- `A` sends: "I would like to obtain the value corresponding to `h(e_j)`, my current level of knowledge is `h(e_i)`"
- `A` initializes the local variable `accumulator` to `v_i`
- `B` looks up `e_j` and then recursively follows links along the shortest path to `e_i`, obtaining the shortest path of events `p_1, p_2, ..., p_x` with `p_1 = e_j` and `p_x = e_i`; if it does not reach `e_i` this way, it politely informs `A` that it cannot be of service
- `B` sends `p_1`, then `p_2`, and so on, up to `p_{x-1}`
- `B` then sends `delta(p_{x-1})`, then `delta(p_{x-2})`, and so on, up to `delta(p_1)`, where `delta(p_i)` is a value `v` such that `h(v) = p_i.predecessor_delta_id` if `p_i.sequence_number = p_{i+1}.sequence_number + 1`, or a value `v` such that `h(v) = p_i.skip_delta_id` otherwise
- when `A` receives `p_j`, it verifies that hashing that value does indeed yield `h(e_j)`
- next, when `A` receives any of the successive events, it verifies that hashing it yields the `predecessor_event_id` or `skip_event_id` of the previously received event, depending on which one is appropriate
- next, when `A` receives `p_{i+1}`, it also verifies that its `predecessor_event_id` or `skip_event_id` is equal to `h(e_i)`, depending on which one is appropriate
- next, when `A` receives some `d_l`, it verifies that hashing it yields the `predecessor_delta_id` or `skip_event_id` of the corresponding event, depending on which one is appropriate, and then updates `accumulator` to `accumulator +_T d_l`

## Precise Encoding

Because magma relies on hashing for integrity verification, the encoding of events must be well-defined. The proceeding text talked about comparing hashes directly, but we can use a slightly more general concept.

Let `T` and `N` be sets, and let `compute_name: T -> N` and `verify_name: (T, N) -> Bool` be functions. We call `(compute_name, verify_name)` a *naming scheme* if for all `t` in `T` we have `verify_name(t, compute_name(t)) = true`. Magma is only as secure as the naming scheme it uses, ideally `verify_name(t, compute_name(u)) = false` for all `u != t`. A typical choice based on some secure hash function `h` would be `compute_name(t) := h(t)` and `verify_name(t, n) := (h(t) == n)`. Naming schemes however also support multihashes, where a name consists of a secure hash together with an indicator which hash function was used to compute it. The verification function then select the appropriate hash function, compute it, and then check for equality.

Magma does not prescribe a particular naming scheme or monoid of values, so the protocol is generic. An instantiation of the protocol requires the following information:

- a monoid `(T, +_T, 0_T)`
- a bijective function `encode_monoid: T -> {0, 1}^*` uniquely mapping monoid values to byte strings
- a naming scheme `(compute_name: {0, 1}^* -> N, verify_name: ({0, 1}^*, N) -> Bool)`
- a `reserved_name` from `N` that can be used to encode that no predecessor exists
- a bijective function `encode_name: N -> {0, 1}^*` uniquely mapping names to byte strings

Given choices for these parameters, a magma *event* logically consists of the following data:

```rust
struct LogicalEvent {
  sequence_number: NonZeroU64, // 1-based index of this event in the evolution of the value

  predecessor_event: Option<LogicalEvent>, // the predecessor event, None if this is the first event
  predecessor_delta: T, // change compared to the predecessor event
  predecessor_delta_size: u64, // size in bytes of this.predecessor_delta

  skip_event: Option<LogicalEvent>, // the skip event, None if this is the first event
  skip_delta: T, // change compared to the skip event
  skip_delta_size: u64, // size in bytes of this.skip_delta
}
```

Such an `e: LogicalEvent` is encoded by `encode_event: LogicalEvent -> {0, 1}^*` as follows:

- begin with `e.sequence_number`, encoded as a canonic [`VarU64`](https://github.com/AljoschaMeyer/varu64)
- if `e.skip_event = Some(se)` and `e.skip_event != e.predecessor_event` append `compute_name(encode_event(se))`, otherwise append `reserved_name`
- if `e.predecessor_event = Some(pe)` append `compute_name(encode_event(pe))`, otherwise append `reserved_name`
- if `e.skip_event != e.predecessor_event`, append `e.skip_delta_size` , encoded as a canonic [`VarU64`](https://github.com/AljoschaMeyer/varu64)
- if `e.skip_event != e.predecessor_event`, append `compute_name(encode_monoid(e.skip_delta))`
- append `e.predecessor_delta_size`, encoded as a canonic [`VarU64`](https://github.com/AljoschaMeyer/varu64)
- append `compute_name(encode_monoid(e.predecessor_delta))`

## Transmission Protocol

We distinguish three distinct phases in the communication for transmitting magma data: the request, the metadata transmission, and the value transmission. We now discuss the different options for the metadata transmission and value transmission phases that the protocol should provide, which then guides the request design and the actual bit-level protocol description.

### Metadata Transmission

The metadata of interest is determined by the name of the event that corresponds to the *target* value of the requesting endpoint wants to fetch, and the name of the *base* event for which the requesting endpoint already knows the value. The requesting endpoint may have no base event available, in which case it transmits the `reserved_name` instead.

If the sequence number of the *target* is greater than or equal to the sequence number of the *base*, then the metadata transmission consists of the events on the shortest path from the *target* to the *base*, otherwise the transmission consists of the events on the shortest path from the *base* to the *target*. If the responding endpoint does not have all that data, it transmits the longest prefix of the path for which it has the data, and then terminates the transmission. If the responding endpoint does not know either the *base* or *target* name, this is merely a special case where the longest prefix has length zero.

Because a response might stop after a prefix of the required metadata (either because of unavailable data or because of a connection loss), it can happen that an endpoint already has a prefix of the metadata that is of interest for a request. To prevent unnecessary retransmission of that metadata, every request contains a number indicating how many of the metadata events to skip over, i.e., the first `x` events of the shortest path are not transmitted. If that number is equal to the length of the path, then no metadata is transmitted at all. Any number greater than the length of that path is treated as if it was the length of the path. A zero simply results in the full path being transmitted.

Sometimes an endpoint is merely interested in how much data *could* be transmitted rather than the data itself. A request thus includes a *dry run* flag.

### Value Transmission

There are a few variations of how values are transmitted. First, a request can be *metadata-only*, indicating that no values shall be transmitted at all. If values are to be transmitted, the request and specify whether they should be transmitted in ascending or descending order. When choosing descending order, it is not necessary to transfer the metadata in advance, the transmission can go metadata, value, metadata, value, ... instead.

If no metadata needs to be transmitted before the first value, the request can indicate that a prefix of the encoding of the value is already available at the requesting endpoint. The request then includes the number of bytes that are already available, and also the name of that prefix.

### Protocol Organization

The protocol is symmetric, and is organized into multiple, independent streams. Each endpoint has three outgoing communication streams, as well as the three corresponding incoming streams.

The first pair of streams is for sending all receiving requests. Backpressure is applied in units of full requests. In addition to the options regarding metadata and value transmissions, a request has a RequestId, a 64 bit integer. This way, multiple requests can be sent before the older ones have been answered. RequestIds should be fresh, the protocol does not specify how an implementation should handle duplicate IDs (this way, implementations can simply assume it never happens - if the other endpoint receives garbage because it duplicated IDs, then that is their fault and problem).

The second pair of streams is for canceling request. A cancellation does not consume any credit, the space requirements for handling cancellation of a request should be reserved when issuing credit for that request. A cancellation specifies the RequestId of the request to be cancelled. After receiving a cancellation, an endpoint should terminate the corresponding response as soon as possible (the same way it would indicate that it was missing any further data). Receiving a cancellation request for an unknown RequestID is an error.

The third pair of streams is for transmitting metadata and values. One credit corresponds to one byte of metadata or value encoding. Value encoding... TODO


- active request

- how to do logs (caching the state of the hash functions at certain points etc.)
- homomorphic hashing as an alternative (probably not of practical relevance?) 
