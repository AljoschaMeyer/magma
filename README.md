# Magma

A specification and protocol for representing and transmitting values that changed over time in an untrusted decentralized setting.

Magma revolves around two concepts: cryptographically secure hashes and monoids. A [cryptographically secure hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function) maps values to short digest which are unique with a very high probability, and even a malicious act there trying to find values that hash to non-unique digest cannot do better than that probability dictates.

A [monoid](https://en.wikipedia.org/wiki/Monoid) is a set of values with a binary operation that is associative and has a neutral element. Monoids can be used to represent values changing over time. Consider for example a variable holding an integer. Rather than representing its evolution over time by keeping a sequence of the values the variable held, you can keep a sequence of the differences between the values. An integer can not only be interpreted as a specific value, but also as an operation that can be applied to a different value by adding it. Even when thinking of an integer as a value, you can interpreted as the operation taking the neutral element (zero) to the desired value.

Magma explores the interplay between these two concepts: monoidal values referring to past values by their hashes. When a datum contains the hash of another datum, this implies that the latter datum must have already existed when the prior datum was created. Such data form a [directed acyclic graph](https://en.wikipedia.org/wiki/Directed_acyclic_graph). Because hashes cannot be forged, any datum authenticates all data it transitively refers to.

This can be used when storing the evolution of a monoidal value over time in a distributed fashion: the value of a variable at a specific point in time can be represented as the monoid value representing the change from the previous value, and the hash of the previous value of the variable. Suppose a peer in the system knows the value at time `t39` and then obtains the hash of the value at time `t42` from a trusted source. This peer can then request the value-hash pairs for time points `t42` to `t40` from any untrusted source, and verify that the values have not been tampered with using the hashes.

The main motivation for such a system is one of preserving bandwidth. The value at time `t42` might be a very large object, but the series of changes leading from the value at time `t39` to the value at time `t42` might be very small. Magma provides a generic framework for representing values and transmitting them in settings where this assumption is reasonable.

## Linear Magma

Linear magma is a simple exploration of the problem space which does not achieve desirable complexity goals. We use it to motivate the designs and then define the actual magma data format as a refinement of linear magma. We begin by giving a bunch of definitions:

Let `(T, +_T, 0_T)` be a monoid, and let `value_sequence = [v_1, v_2, ..., v_k]` be a sequence of values of type `T`. We then call `delta_sequence = [d_1, d_2, ..., d_k]` the corresponding sequence such that `d_1 +_T d_2 +_T ... +_T d_i = v_i` for all `0 <= i <= k`.

Let `h` be a secure hash function. An `Event` consists of a `predecessor_delta_id` which is the digest of some value of type `T`, and the `predecessor_event_id` which is either the digest of an `Event` or the digest zero. For a `value_sequence = [v_1, v_2, ..., v_k]` with `delta_sequence = [d_1, d_2, ..., d_k]`, the corresponding `event_sequence = [e_1, e_2, ..., e_k]` is recursively defined as `e_1 = Event { predecessor_delta_id = h(d_1), predecessor_event_id = 0 }`, `e_i = Event { predecessor_delta_id = h(d_i), predecessor_event_id = h(e_{i-1}) }`.

Now suppose `A` is a peer that knows the values `v_i` and `e_i` for some `1 <= i < k`, and `h(e_j)` for some `i < j <= k`. `B` is a peer that knows the full `delta_sequence`, `event_sequence`, and can efficiently map the hash of any known event to the corresponding event value. `A` wants to obtain `v_j` by communicating with `B`, but does not trust `B`. This can be achieved through the following sequence of events:

- `A` sends: "I would like to obtain the value corresponding to `h(e_j)`, my current level of knowledge is `h(e_i)`"
- `A` initializes the local variable `accumulator` to `v_i`
- `B` looks up `e_j` and then recursively looks up the predecessor events until it finds `e_i`; if it does not reach `e_i` this way, it politely informs `A` that it cannot be of service
- `B` sends `e_j`, then `e_{l-1}`, and so on, up to `e_{i+1}`
- `B` then sends `d_{i+1}`, then `d_{i+2}`, and so on, up to `d_j`
- when `A` receives `e_j`, it verifies that hashing that value does indeed yield `h(e_j)`
- next, when `A` receives any of the successive events, it verifies that hashing it yields the `predecessor_event_id` of the previously received event
- next, when `A` receives `e_{i+1}`, it verifies that its `predecessor_event_id` is equal to `h(e_i)`
- next, when `A` receives some `d_l`, it verifies that hashing it yields the `predecessor_delta_id` of `e_l`, and then updates `accumulator` to `accumulator +_T d_l`

This exchange enables `A` to detect if `B` tries to send invalid data. Because events include hashes of monoid values rather than the values themselves, the number of bytes transferred in the initial phase of `B`'s transmission does not depend on the size of the values.

There is however still a denial of service attack `B` can perform: rather than sending `d_{l+1}`, it can send an arbitrarily long string of garbage. `A` has to patiently compute its hash, not knowing that the input to the hash function will never end.

To protect against this, we add a third datum to each event `e_i`: `predecessor_delta_size`, the number of bytes in the transport encoding of `d_i`. This information allows `A` to drop the connection when a value transmitted by `B` exceeds the size promised in its corresponding event. This mechanism can only work if the `predecessor_delta_size` of all events in circulation is accurate, for that reason `A` has to reject a potential `d_l` if it is too small as well, even if the hash is correct.

This protocol has exhibits complexities: `B` sends `j - i` many events, and `A` has to store that many events in memory in order to check the integrity of the following delta sequence. We now describe the real magma protocol, which employs a [binary anti-monotone linking scheme](TODO) to reduce these complexities to `O(log(j - i))`. The remainder of this text assumes familiarity with the concepts and terminology introduced in that link.

## Logarithmic Complexities
