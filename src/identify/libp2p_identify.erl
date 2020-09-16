-module(libp2p_identify).

-include("pb/libp2p_identify_pb.hrl").

-type identify() :: #libp2p_signed_identify_pb{}.
-type identify_map() :: #{
    pubkey_bin => libp2p_crypto:pubkey_bin(),
    observed_addr => string(),
    nonce => binary()
}.

-export_type([identify/0, identify_map/0]).

-export([
    from_map/2,
    encode/1,
    decode/1,
    verify/1,
    pubkey_bin/1,
    observed_maddr/1,
    observed_addr/1,
    nonce/1
]).

%% @doc Constructs a signed identify from a given map of infomration.
-spec from_map(identify_map(), libp2p_crypto:sig_fun()) -> {ok, identify()} | {error, term()}.
from_map(
    #{
        pubkey_bin := PubKeyBin,
        observed_addr := ObservedAddr,
        nonce := Nonce
    },
    SigFun
) ->
    Identify = #libp2p_identify_pb{
        pubkey = PubKeyBin,
        observed_addr = multiaddr:new(ObservedAddr),
        nonce = Nonce
    },
    case SigFun(libp2p_identify_pb:encode_msg(Identify)) of
        {error, Error} -> {error, Error};
        Signature -> {ok, #libp2p_signed_identify_pb{identify = Identify, signature = Signature}}
    end.

%% @doc Gets the public key of the given identity. The key is in
%% binary form.
-spec pubkey_bin(identify()) -> libp2p_crypto:pubkey_bin().
pubkey_bin(#libp2p_signed_identify_pb{identify = #libp2p_identify_pb{pubkey = PubKeyBin}}) ->
    PubKeyBin.

%% @doc Gets the observed address from the identify.
%%
%% @see observed_maddr/1
-spec observed_addr(identify()) -> string().
observed_addr(Identify = #libp2p_signed_identify_pb{}) ->
    multiaddr:to_string(observed_maddr(Identify)).

%% @doc Gtes the encoded (multiaddress binary) form of the observed
%% address of the given identify
observed_maddr(#libp2p_signed_identify_pb{
    identify = #libp2p_identify_pb{observed_addr = ObservedAddr}
}) ->
    ObservedAddr.

%% @doc Fetches the nonce from the given identify
-spec nonce(identify()) -> binary().
nonce(#libp2p_signed_identify_pb{identify = #libp2p_identify_pb{nonce = Nonce}}) ->
    Nonce.

%% @doc Encodes the given identify into its binary form.
-spec encode(identify()) -> binary().
encode(Msg = #libp2p_signed_identify_pb{}) ->
    libp2p_identify_pb:encode_msg(Msg).

%% @doc Decodes a given binary into an identify. The resulting
%% identify is verified
-spec decode(binary()) -> {ok, identify()} | {error, term()}.
decode(Bin) ->
    try
        Msg = libp2p_identify_pb:decode_msg(Bin, libp2p_signed_identify_pb),
        verify(Msg)
    catch
        _:_ -> {error, invalid_binary}
    end.

%% @doc Cryptographically verifies a given identify.
-spec verify(identify()) -> {ok, identify()} | {error, term()}.
verify(
    Msg = #libp2p_signed_identify_pb{
        identify = Ident = #libp2p_identify_pb{},
        signature = Signature
    }
) ->
    EncodedIdentify = libp2p_identify_pb:encode_msg(Ident),
    PubKey = libp2p_crypto:bin_to_pubkey(pubkey_bin(Msg)),
    case libp2p_crypto:verify(EncodedIdentify, Signature, PubKey) of
        true -> {ok, Msg};
        false -> {error, invalid_signature}
    end.
