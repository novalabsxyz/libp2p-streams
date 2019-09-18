-module(libp2p_stream_secure).


-behavior(libp2p_stream).

%% API
-export([dial/2, mk_keypair/1]).
%% libp2p_stream
-export([init/2,
         handle_packet/4,
         handle_command/4,
         handle_info/3
        ]).

-type secure_keymap() :: #{ public => binary(), secret => binary(), signature => binary()}.

-record(state, {
                mod :: atom(),
                mod_opts :: map(),
                mod_state :: any(),
                peer_address :: string() | undefined,
                identify_address=undefined :: string() | undefined,
                exchanged = false :: boolean(),
                secure_keys :: secure_keymap(),
                secure_timeout :: non_neg_integer(),
                rcv_key = <<>> :: binary(),
                send_key = <<>> :: binary(),
                send_nonce = 0 :: non_neg_integer(),
                rcv_nonce = 0 :: non_neg_integer(),
                packet_spec = undefined :: libp2p_packet:spec() | undefined
               }).

-define(DEFAULT_SECURE_TIMEOUT, 10000).
%%
%% API
%%

-spec mk_keypair(libp2p_crypto:sig_fun()) -> secure_keymap().
mk_keypair(SigFun) ->
    KeyPair = #{public := PubKey} = enacl:kx_keypair(),
    Signature = SigFun(PubKey),
    KeyPair#{signature => Signature}.

dial(Muxer, #{handlers := [{Protocol, {Mod, ModOpts}}],
              secure_keys := SecureKeys,
              identify_keys := IdentifyKeys,
              peer_address := PeerAddress
             }) ->
    Handlers = [{Protocol, {?MODULE, #{mod => Mod,
                                       mod_opts => ModOpts,
                                       peer_address => PeerAddress,
                                       identify_keys => IdentifyKeys,
                                       secure_keys => SecureKeys}}}],
    libp2p_stream_muxer:dial(Muxer, #{ handlers => Handlers} ).


init(Kind, Opts=#{ secure_keys := SecureKeys,
                    identify_keys := IdentKeys,
                    mod := Mod}) ->
    libp2p_stream_md:update({stack, {Mod, Kind}}),
    %% Kick of an identify
    Muxer = libp2p_stream_md:get(muxer),
    libp2p_stream_muxer:identify(Muxer, #{ identify_keys => IdentKeys,
                                           identify_handler => {self(), stream_secure_identify}
                                         }),

    %% Proceed assuming we'll get the right identify back
    SecureTimeout = maps:get(secure_timeout, Opts, ?DEFAULT_SECURE_TIMEOUT),
    {ok, #state{mod=Mod,
                mod_opts=maps:get(mod_opts, Opts, #{}),
                secure_keys=SecureKeys,
                secure_timeout=SecureTimeout,
                peer_address=maps:get(peer_address, Opts, undefined)},
     [{packet_spec, [varint]}]
    }.


handle_packet(Kind, _, Packet, State=#state{exchanged=false}) ->
    case Packet of
        <<ExPubKey:32/binary, Signature/binary>> ->
            RemotePubKeyBin = libp2p_crypto:p2p_to_pubkey_bin(State#state.identify_address),
            RemotePubKey = libp2p_crypto:bin_to_pubkey(RemotePubKeyBin),
            case libp2p_crypto:verify(ExPubKey, Signature, RemotePubKey) of
                false ->
                    lager:notice("Invalid signature on key exchange"),
                    {stop, normal, State};
                true ->
                    {RcvKey, SendKey} = rcv_and_send_keys(Kind, State#state.secure_keys, ExPubKey),
                    Result = (State#state.mod):init(Kind, State#state.mod_opts),
                    handle_init_result(Result, State#state{exchanged=true,
                                                           send_key=SendKey,
                                                           rcv_key=RcvKey})
            end;
        Other ->
            lager:notice("Invalid secure handshake: ~p", [Other]),
            {stop, normal, State}
    end;
handle_packet(Kind, _, Data, State0=#state{exchanged=true, mod=Mod, rcv_nonce=Nonce}) ->
    State = State0#state{rcv_nonce=Nonce + 1},
    case decrypt_data(Data, State#state.rcv_key, Nonce) of
        {error, Error} ->
            lager:notice("Error decrypting data: ~p", [Error]),
            {stop, normal, State};
        {ok, Bin} ->
            %% Decryped the envelope, now decode the packet as
            %% indicated by the packet_spec of the managed module
            case libp2p_packet:decode_packet(State#state.packet_spec, Bin) of
                {ok, Header, Packet, _} ->
                    Result = Mod:handle_packet(Kind, Header, Packet, State#state.mod_state),
                    %% Dispatch the result of handling the packet
                    handle_info_result(Result, State);
                {more, _N} ->
                    lager:error("Decrypted packet not complete for spec ~p", [State#state.packet_spec]),
                    {stop, normal, State}
            end
    end.


handle_command(Kind, Cmd, From, State=#state{mod=Mod, mod_state=ModState}) ->
    case erlang:function_exported(Mod, handle_command, 4) of
        true->
            Result = Mod:handle_command(Kind, Cmd, From, ModState),
            handle_command_result(Result, State);
        false ->
            lager:warning("Unhandled ~p callback call: ~p", [Kind, Cmd]),
            {reply, ok, State}
    end.


handle_info(_Kind, {handle_identify, stream_secure_identify, {error, Error}}, State=#state{}) ->
    {_, RemoteAddr} = libp2p_stream_md:get(addr_info),
    lager:notice("Failed to identify ~p: ~p", [RemoteAddr, Error]),
    {stop, normal, State};
handle_info(_Kind, {handle_identify, stream_secure_identify, {ok, Identify}},
            State=#state{peer_address=PeerAddr,
                         secure_keys=#{ public := PubKey, signature := Signature}}) ->
    IdentifyAddr = libp2p_crypto:pubkey_bin_to_p2p(libp2p_identify:pubkey_bin(Identify)),
    libp2p_stream_md:update({identify, Identify}),
    case PeerAddr == undefined orelse IdentifyAddr == PeerAddr of
        false ->
            lager:notice("Received identify ~p does not match expected ~p", [IdentifyAddr, PeerAddr]),
            {stop, normal, State};
        true ->
            Data = <<PubKey/binary, Signature/binary>>,
            {noreply, State#state{identify_address=IdentifyAddr},
             [{send, encode_data(Data)},
              {active, once},
              {timer, secure_timeout, State#state.secure_timeout}]
             }
    end;
handle_info(Kind, Msg, State=#state{mod=Mod}) ->
    case erlang:function_exported(Mod, handle_info, 3) of
        true->
            Result = Mod:handle_info(Kind, Msg, State#state.mod_state),
            handle_info_result(Result, State);
        false ->
            lager:warning("Unhandled ~p callback info: ~p", [Kind, Msg]),
            {noreply, State}
    end.


%%
%% Utilities
%%

handle_init_result({ok, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {noreply, NewState, NewActions};
handle_init_result({stop, Reason}, State) ->
    {stop, Reason, State};
handle_init_result({stop, Reason, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {stop, Reason, NewState, NewActions};
handle_init_result(Result, State) ->
    {stop, {error, {invalid_init_result, Result}}, State}.


handle_info_result({noreply, ModState}, State) ->
    {noreply, State#state{mod_state=ModState}};
handle_info_result({noreply, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {noreply, NewState, NewActions};
handle_info_result({stop, Reason, ModState}, State) ->
    {stop, Reason, State#state{mod_state=ModState}};
handle_info_result({stop, Reason, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {stop, Reason, NewState, NewActions}.


handle_command_result({reply, Reply, ModState}, State) ->
    {reply, Reply, State#state{mod_state=ModState}};
handle_command_result({reply, Reply, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {reply, Reply, NewState, NewActions};
handle_command_result({noreply, ModState}, State) ->
    {noreply, State#state{mod_state=ModState}};
handle_command_result({noreply, ModState, Actions}, State) ->
    {NewState, NewActions} = handle_actions(Actions, {State#state{mod_state=ModState}, []}),
    {noreply, NewState, NewActions}.


-spec handle_actions(libp2p_stream:actions(), {#state{}, libp2p_stream:actions()})
                    -> {#state{}, libp2p_stream:actions()}.
handle_actions([], {State, Acc}) ->
    {State, lists:reverse(Acc)};
handle_actions([{packet_spec, Spec} | Tail], {State, Acc}) ->
    handle_actions(Tail, {State#state{packet_spec=Spec}, Acc});
handle_actions([{send, Data} | Tail], {State=#state{send_nonce=Nonce}, Acc}) ->
    {ok, EncryptedData} = encrypt_data(Data, State#state.send_key, Nonce),
    handle_actions(Tail, {State#state{send_nonce=Nonce + 1}, [{send, encode_data(EncryptedData)} | Acc]});
handle_actions([{swap, _Mod, _ModOpts} | Tail], {State, Acc}) ->
    %% @todo implement
    handle_actions(Tail, {State, Acc});
handle_actions([Action | Tail], {State, Acc}) ->
    handle_actions(Tail, {State, [Action | Acc]}).



-spec encode_data(binary()) -> binary().
encode_data(Data) ->
    libp2p_packet:encode_packet([varint], [byte_size(Data)], Data).

-spec encrypt_data(Data::binary(), Key::binary(), Nonce::non_neg_integer()) ->
                          {ok, binary()} | {error, term()}.
encrypt_data(Data, Key, Nonce) ->
    case enacl:aead_chacha20poly1305_encrypt(Key, Nonce, <<>>, Data) of
        {error, Error} -> {error, Error};
        Bin -> {ok, Bin}
    end.


-spec decrypt_data(Data::binary(), Key::binary(), Nonce::non_neg_integer())
                  -> {ok, binary()} | {error, term()}.
decrypt_data(Data, Key, Nonce) ->
    case enacl:aead_chacha20poly1305_decrypt(Key, Nonce, <<>>, Data) of
        {error, Error} -> {error, Error};
        Bin -> {ok, Bin}
    end.


rcv_and_send_keys(client, #{ public := ClientPK, secret := ClientSK }, ServerPK) ->
    #{client_rx := RcvKey, client_tx := SendKey} =
        enacl:kx_client_session_keys(ClientPK, ClientSK, ServerPK),
    {RcvKey, SendKey};
rcv_and_send_keys(server, #{ public := ServerPK, secret := ServerSK}, ClientPK) ->
    #{server_rx := RcvKey, server_tx := SendKey} =
        enacl:kx_server_session_keys(ServerPK, ServerSK, ClientPK),
    {RcvKey, SendKey}.




-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

encrypt_decrypt_test() ->
    SKeyPair= #{ public := SPubKey} = enacl:kx_keypair(),
    CKeyPair= #{ public := CPubKey} = enacl:kx_keypair(),

    {CRcvKey, CSendKey} = rcv_and_send_keys(client, CKeyPair, SPubKey),
    {SRcvKey, SSendKey} = rcv_and_send_keys(server, SKeyPair, CPubKey),

    Data = <<"hello world">>,
    %% Send from client, decrypt on server
    {ok, CEData} = encrypt_data(Data, CSendKey, 1),
    ?assertEqual({ok, Data}, decrypt_data(CEData, SRcvKey, 1)),

    %% Send from server, decrypt on client
    {ok, SEData} = encrypt_data(Data, SSendKey, 1),
    ?assertEqual({ok, Data}, decrypt_data(SEData, CRcvKey, 1)),

    %% Fail decrypt
    ?assertMatch({error, _}, decrypt_data(encode_data(SEData), CRcvKey, 1)),

    ok.



-endif.
