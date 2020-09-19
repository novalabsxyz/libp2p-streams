-module(libp2p_key).

-include_lib("public_key/include/public_key.hrl").

-include("pb/libp2p_key_pb.hrl").

-record(private_key, {
    type :: type(),
    data :: private_data()
}).

-record(public_key, {
    type :: type(),
    data :: public_data()
}).

-type type() :: ed25519 | rsa.
-type public() :: #public_key{}.
-type private() :: #private_key{}.

-type public_data() :: ed25519_public_key() | rsa_public_key().
-type private_data() :: ed25519_private_key() | rsa_private_key().

-type ed25519_public_key() :: <<_:256>>.
-type ed25519_private_key() :: <<_:256>>.

-type rsa_public_key() :: #'RSAPublicKey'{}.
-type rsa_private_key() :: #'RSAPrivateKey'{}.

-export_type([type/0, public/0, private/0]).

-export([
    mk_public/2,
    mk_private/2,
    type/1,
    sign/2,
    verify/3,
    to_proto/1,
    from_proto/1,
    encode/1,
    decode/2
]).

-spec mk_public(type(), public_data()) -> public().
mk_public(Type, Data) ->
    #public_key{type = Type, data = Data}.

-spec mk_private(type(), private_data()) -> private().
mk_private(Type, Data) ->
    #private_key{type = Type, data = Data}.

-spec type(public() | private()) -> {public | private, type()}.
type(#public_key{type = Type}) ->
    {public, Type};
type(#private_key{type = Type}) ->
    {private, Type}.

-spec sign(private(), Msg :: binary()) -> binary().
sign(#private_key{type = ed25519, data = Data}, Msg) ->
    enacl:sign_detached(Msg, Data);
sign(#private_key{type = rsa, data = Data}, Msg) ->
    public_key:sign(Msg, sha256, Data).

-spec verify(public(), Signature :: binary(), Msg :: binary()) -> boolean().
verify(#public_key{type = ed25519, data = Data}, Signature, Msg) ->
    case enacl:sign_verify_detached(Signature, Msg, Data) of
        {ok, _} -> true;
        _ -> false
    end;
verify(#public_key{type = rsa, data = Data}, Signature, Msg) ->
    public_key:verify(Msg, sha256, Signature, Data).

-spec to_proto(public() | private()) -> #libp2p_public_key_pb{} | #libp2p_private_key_pb{}.
to_proto(#public_key{type = Type, data = Data}) ->
    #libp2p_public_key_pb{
        type = Type,
        data = encode_data(public, Type, Data)
    };
to_proto(#private_key{type = Type, data = Data}) ->
    #libp2p_private_key_pb{
        type = Type,
        data = encode_data(private, Type, Data)
    }.

-spec from_proto(#libp2p_public_key_pb{} | #libp2p_private_key_pb{}) -> public() | private().
from_proto(#libp2p_public_key_pb{type = Type, data = Data}) ->
    DecodedData = decode_data(public, Type, Data),
    #public_key{type = Type, data = DecodedData};
from_proto(#libp2p_private_key_pb{type = Type, data = Data}) ->
    DecodedData = decode_data(private, Type, Data),
    #private_key{type = Type, data = DecodedData}.

-spec encode(public() | private()) -> binary().
encode(Key) ->
    libp2p_key_pb:encode_msg(to_proto(Key)).

-spec decode(publc | private, binary()) -> public() | private().
decode(public, Bin) ->
    from_proto(libp2p_key_pb:decode_msg(Bin, libp2p_public_key_pb));
decode(private, Bin) ->
    from_proto(libp2p_key_pb:decode_msg(Bin, libp2p_private_key_pb)).

encode_data(_, ed25519, Data) ->
    Data;
encode_data(public, rsa, Data) ->
    public_key:der_encode('RSAPublicKey', Data);
encode_data(private, rsa, Data) ->
    public_key:der_encode('RSAPrivateKey', Data).

decode_data(_, ed25519, Data) ->
    Data;
decode_data(public, rsa, Data) ->
    public_key:der_decode('RSAPublicKey', Data);
decode_data(private, rsa, Data) ->
    public_key:der_decode('RSAPrivateKey', Data).
