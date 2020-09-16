-module(libp2p_stream_identify).

-behavior(libp2p_stream).

%% API
-export([handler/1]).
%% libp2p_stream
-export([
    init/2,
    handle_packet/4,
    handle_info/3,
    protocol_id/0
]).

-define(DEFAULT_IDENTIFY_TIMEOUT, 5000).

-record(state, {
    pubkey_bin :: libp2p_crypto:pubkey_bin(),
    sig_fun :: libp2p_crypto:sig_fun(),
    identify_handler = undefined :: {ResultPid :: pid(), ResultData :: any()} | undefined
}).

%%
%% API
%%

handler(Opts) ->
    {protocol_id(), {?MODULE, Opts}}.

protocol_id() ->
    <<"/identify/2.0.0">>.

init(
    client,
    Opts = #{
        identify_keys := #{pubkey_bin := PubKeyBin, sig_fun := SigFun},
        identify_handler := {ResultPid, ResultData}
    }
) ->
    Challenge = crypto:strong_rand_bytes(20),
    State = #state{
        pubkey_bin = PubKeyBin,
        sig_fun = SigFun,
        identify_handler = {ResultPid, ResultData}
    },
    IdentifyTimeout = maps:get(identify_timeout, Opts, ?DEFAULT_IDENTIFY_TIMEOUT),
    case mk_identify(Challenge, State) of
        {ok, Identify} ->
            {ok, State, [
                {send, encode_identify(Identify)},
                {active, once},
                {packet_spec, [varint]},
                {timer, identify_timeout, IdentifyTimeout}
            ]};
        {error, Error} ->
            notify_identify_handler({error, Error}, State),
            {stop, {error, Error}}
    end;
init(server, Opts = #{identify_keys := #{pubkey_bin := PubKeyBin, sig_fun := SigFun}}) ->
    IdentifyTimeout = maps:get(identify_timeout, Opts, ?DEFAULT_IDENTIFY_TIMEOUT),
    State = #state{
        pubkey_bin = PubKeyBin,
        sig_fun = SigFun
    },
    {ok, State, [
        {active, once},
        {packet_spec, [varint]},
        {timer, identify_timeout, IdentifyTimeout}
    ]}.

handle_packet(client, _, Packet, State = #state{}) ->
    Result = libp2p_identify:decode(Packet),
    notify_identify_handler(Result, State),
    {stop, normal, State};
handle_packet(server, _, Packet, State = #state{}) ->
    case libp2p_identify:decode(Packet) of
        {ok, Identify} ->
            Challenge = libp2p_identify:nonce(Identify),
            case mk_identify(Challenge, State) of
                {ok, ResponseIdentify} ->
                    {stop, normal, State, [{send, encode_identify(ResponseIdentify)}]};
                {error, Error} ->
                    lager:warning("Failed to construct identify: ~p", [Error]),
                    {stop, normal, State}
            end;
        {error, Error} ->
            lager:warning("Received invalid identify request: ~p", [Error]),
            {stop, normal, State}
    end.

handle_info(_Kind, {timeout, identify_timeout}, State = #state{}) ->
    {_, RemoteAddr} = libp2p_stream_md:get(addr_info),
    lager:notice("Identify ~p timeout with ~p", [_Kind, RemoteAddr]),
    notify_identify_handler({error, identify_timeout}, State),
    {stop, normal, State};
handle_info(Kind, Msg, State = #state{}) ->
    lager:warning("Unhandled ~p info ~p", [Kind, Msg]),
    {noreply, State}.

%%
%% Internal
%%

-spec mk_identify(Challenge :: binary(), #state{}) ->
    {ok, libp2p_identify:identify()} | {error, term()}.
mk_identify(Challenge, State = #state{}) ->
    {_, RemoteAddr} = libp2p_stream_md:get(addr_info),
    libp2p_identify:from_map(
        #{
            pubkey_bin => State#state.pubkey_bin,
            nonce => Challenge,
            observed_addr => RemoteAddr
        },
        State#state.sig_fun
    ).

encode_identify(Identify) ->
    Bin = libp2p_identify:encode(Identify),
    libp2p_packet:encode_packet([varint], [byte_size(Bin)], Bin).

notify_identify_handler(_Notify, #state{identify_handler = undefined}) ->
    ok;
notify_identify_handler(Notify, #state{identify_handler = {ResultPid, ResultData}}) ->
    ResultPid ! {handle_identify, ResultData, Notify},
    ok.
