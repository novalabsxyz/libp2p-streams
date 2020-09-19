-module(libp2p_peer_id).

-export([from_public_key/1, to_string/1, from_string/1, from_bytes/1, to_bytes/1]).

-record(peer_id, {
    data :: binary()
}).

-type id() :: #peer_id{}.

-spec from_public_key(libp2p_key:public()) -> id().
from_public_key(Key) ->
    Encoded = libp2p_key:encode(Key),
    {ok, Digest} =
        case byte_size(Encoded) > 42 of
            false -> multihash:digest(Encoded, identity);
            true -> multihash:digest(Encoded, sha2_256)
        end,
    #peer_id{data = Digest}.

-spec to_string(id()) -> string().
to_string(#peer_id{data = Data}) ->
    base58:binary_to_base58(Data).

-spec from_string(string()) -> id().
from_string(Str) ->
    Data = base58:base58_to_binary(Str),
    #peer_id{data = Data}.

-spec to_bytes(id()) -> binary().
to_bytes(#peer_id{data = Data}) ->
    Data.

-spec from_bytes(binary()) -> id().
from_bytes(Data) ->
    #peer_id{data = Data}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

string_test() ->
    EdPubKey = libp2p_keypair:public_key(libp2p_keypair:new(ed25519)),
    EdPeerId = from_public_key(EdPubKey),
    ?assertEqual(EdPeerId, from_string(to_string(EdPeerId))),
    ?assertEqual(to_string(EdPeerId), string:find(to_string(EdPeerId), "1")),

    RSAPubKey = libp2p_keypair:public_key(libp2p_keypair:new(rsa)),
    RSAPeerId = from_public_key(RSAPubKey),
    ?assertEqual(RSAPeerId, from_string(to_string(RSAPeerId))),
    ?assertEqual(to_string(RSAPeerId), string:find(to_string(RSAPeerId), "Qm")),

    ok.

bytes_test() ->
    EdPubKey = libp2p_keypair:public_key(libp2p_keypair:new(ed25519)),
    EdPeerId = from_public_key(EdPubKey),
    ?assertEqual(EdPeerId, from_bytes(to_bytes(EdPeerId))),

    RSAPubKey = libp2p_keypair:public_key(libp2p_keypair:new(rsa)),
    RSAPeerId = from_public_key(RSAPubKey),
    ?assertEqual(RSAPeerId, from_bytes(to_bytes(RSAPeerId))),

    ok.

-endif.
