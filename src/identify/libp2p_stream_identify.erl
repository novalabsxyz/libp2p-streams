-module(libp2p_stream_identify).

-behavior(libp2p_stream).

%% API
-export([dial/2]).
%% libp2p_stream
-export([init/2,
         handle_packet/4,
         handle_info/3,
         protocol_id/0
        ]).

-define(DEFAULT_IDENTIFY_TIMEOUT, 5000).

-record(state, {
                pubkey_bin :: libp2p_crypto:pubkey_bin(),
                sig_fun :: libp2p_crypto:sig_fun(),
                handlers :: libp2p_stream_multistream:handlers()
       }).

%%
%% API
%%

dial(Muxer, Opts = #{ pubkey_bin := _PubKeyBin, sig_fun := _SigFun }) ->
    libp2p_stream_muxer:dial(Muxer, #{ handlers => [ {?MODULE:protocol_id(), {?MODULE, Opts}} ] }).


protocol_id() ->
    <<"/identify/2.0.0">>.

init(client, Opts=#{ pubkey_bin := PubKeyBin, sig_fun := SigFun }) ->
    Challenge = crypto:strong_rand_bytes(20),
    State = #state{pubkey_bin=PubKeyBin,
                   sig_fun=SigFun,
                   handlers=maps:get(handlers, Opts, [])
                  },
    IdentifyTimeout = maps:get(identify_timeout, Opts, ?DEFAULT_IDENTIFY_TIMEOUT),
    case mk_identify(Challenge, State) of
        {ok, Identify} ->
            {ok, State,
             [{send, encode_identify(Identify)},
              {active, once},
              {packet_spec, [varint]},
              {timer, identify_timeout, IdentifyTimeout}
             ]};
        {error, Error} ->
            lager:warning("Failed to construct identify: ~p", [Error]),
            {stop, {error, Error}}
    end;
init(server, Opts=#{ pubkey_bin := PubKeyBin, sig_fun := SigFun }) ->
    IdentifyTimeout = maps:get(identify_timeout, Opts, ?DEFAULT_IDENTIFY_TIMEOUT),
    State = #state{
               pubkey_bin=PubKeyBin,
               sig_fun=SigFun,
               handlers=[]
              },
    {ok, State,
     [{active, once},
      {packet_spec, [varint]},
      {timer, identify_timeout, IdentifyTimeout}
     ]}.


handle_packet(client, _, Packet, State=#state{}) ->
    case libp2p_identify:decode(Packet)  of
        {ok, Identify} ->
            libp2p_stream_transport:update(stream_identify, Identify),
            Muxer = libp2p_stream_transport:get(stream_muxer),
            Muxer ! {stream_identify, Identify},
            case State#state.handlers of
                [] ->
                    {stop, normal, State};
                Handlers ->
                    libp2p_stream_muxer:dial(Muxer, #{ handlers => Handlers }),
                    {stop, normal, State}
            end;
        {error, Error} ->
            lager:warning("Received invalid identify response: ~p", [Error]),
            {stop, normal, State}
    end;
handle_packet(server, _, Packet, State=#state{}) ->
    case libp2p_identify:decode(Packet) of
        {ok, Identify} ->
            Challenge = libp2p_identify:nonce(Identify),
            case mk_identify(Challenge, State) of
                {ok, ResponseIdentify} ->
                    {stop, normal, State,
                     [{send, encode_identify(ResponseIdentify)}]};
                {error, Error} ->
                    lager:warning("Failed to construct identify: ~p", [Error])
            end;
        {error, Error} ->
            lager:warning("Received invalid identify request: ~p", [Error]),
            {stop, normal, State}
    end.


handle_info(_Kind, {timeout, identify_timeout}, State=#state{}) ->
    {_, RemoteAddr} = libp2p_stream_transport:get(stream_addr_info),
    lager:notice("Identify ~p timeout with ~p", [_Kind, RemoteAddr]),
    {stop, normal, State};

handle_info(Kind, Msg, State=#state{}) ->
    lager:warning("Unhandled ~p info ~p", [Kind, Msg]),
    {noreply, State}.

%%
%% Internal
%%


-spec mk_identify(Challenge::binary(), #state{}) -> {ok, libp2p_identify:identify()} | {error, term()}.
mk_identify(Challenge, State=#state{}) ->
    {_, RemoteAddr} = libp2p_stream_transport:get(stream_addr_info),
    libp2p_identify:from_map(#{pubkey_bin => State#state.pubkey_bin,
                               nonce => Challenge,
                               observed_addr => RemoteAddr},
                             State#state.sig_fun).

encode_identify(Identify) ->
    Bin = libp2p_identify:encode(Identify),
    libp2p_packet:encode_packet([varint], [byte_size(Bin)], Bin).
