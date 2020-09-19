-module(libp2p_keypair).

-include_lib("public_key/include/public_key.hrl").

-export([new/1, new/2, public_key/1, private_key/1, sign/2, verify/3]).

-record(keypair, {
    private :: libp2p_key:private(),
    public :: libp2p_key:public()
}).

-type keypair() :: #keypair{}.

new(rsa) ->
    new(rsa, {2048, 65537});
new(Type) ->
    new(Type, undefined).

new(ed25519, _) ->
    #{public := PubKey, secret := PrivKey} = enacl:crypto_sign_ed25519_keypair(),
    #keypair{
        private = libp2p_key:mk_private(ed25519, PrivKey),
        public = libp2p_key:mk_public(ed25519, PubKey)
    };
new(rsa, {Size, PubExp}) ->
    PrivKey = public_key:generate_key({rsa, Size, PubExp}),
    PubKey = #'RSAPublicKey'{
        modulus = PrivKey#'RSAPrivateKey'.modulus,
        publicExponent = PrivKey#'RSAPrivateKey'.publicExponent
    },
    #keypair{
        private = libp2p_key:mk_private(rsa, PrivKey),
        public = libp2p_key:mk_public(rsa, PubKey)
    }.

-spec public_key(keypair()) -> libp2p_key:public().
public_key(#keypair{public = Public}) ->
    Public.

-spec private_key(keypair()) -> libp2p_key:private().
private_key(#keypair{private = Private}) ->
    Private.

-spec sign(Keypair :: keypair(), Msg :: binary()) -> Signature :: binary().
sign(#keypair{private = Private}, Msg) ->
    libp2p_key:sign(Private, Msg).

-spec verify(Keypair :: keypair(), Signature :: binary(), Msg :: binary()) -> boolean().
verify(#keypair{public = Public}, Signature, Msg) ->
    libp2p_key:verify(Public, Signature, Msg).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

sign_verify_test() ->
    Msg = <<"hello world">>,

    RSAKeypair = new(rsa),
    ?assert(verify(RSAKeypair, sign(RSAKeypair, Msg), Msg)),

    EDKeypair = new(ed25519),
    ?assert(verify(EDKeypair, sign(EDKeypair, Msg), Msg)),

    ok.

encode_decode_test() ->
    EDKeypair = new(ed25519),

    ?assertEqual({public, ed25519}, libp2p_key:type(public_key(EDKeypair))),
    ?assertEqual({private, ed25519}, libp2p_key:type(private_key(EDKeypair))),
    ?assertEqual(
        public_key(EDKeypair),
        libp2p_key:decode(public, libp2p_key:encode(public_key(EDKeypair)))
    ),
    ?assertEqual(
        private_key(EDKeypair),
        libp2p_key:decode(private, libp2p_key:encode(private_key(EDKeypair)))
    ),

    RSAKeypair = new(rsa),
    ?assertEqual({public, rsa}, libp2p_key:type(public_key(RSAKeypair))),
    ?assertEqual({private, rsa}, libp2p_key:type(private_key(RSAKeypair))),
    ?assertEqual(
        public_key(RSAKeypair),
        libp2p_key:decode(public, libp2p_key:encode(public_key(RSAKeypair)))
    ),
    ?assertEqual(
        private_key(RSAKeypair),
        libp2p_key:decode(private, libp2p_key:encode(private_key(RSAKeypair)))
    ),

    ok.

-endif.
