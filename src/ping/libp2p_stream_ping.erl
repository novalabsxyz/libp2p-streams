-module(libp2p_stream_ping).

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

-define(PING_SIZE, 32).
-define(PACKET_SPEC, {size, ?PING_SIZE}).

-define(DEFAULT_TIMEOUT_SECS, 20).
-define(DEFAULT_INTERVAL_SECS, 15).
-define(DEFAULT_MAX_FAILURES, 1).

-record(state, {
    %% configuration
    timeout :: pos_integer(),
    interval :: pos_integer(),
    max_failures :: non_neg_integer(),
    %% running state
    failures = 0 :: non_neg_integer(),
    ping = <<>> :: binary()
}).

%%
%% API
%%

handler(Opts) ->
    {protocol_id(), {?MODULE, Opts}}.

protocol_id() ->
    <<"/ipfs/ping/1.0.0">>.

init(
    client,
    Opts
) ->
    lager:debug("init ping client with opts", [Opts]),
    Ping = mk_ping(),
    State = mk_state(Opts),
    {ok, State#state{ping = Ping}, [
        {active, once},
        {send, encode_ping(Ping)},
        {timeout, {ping_timeout, Ping}, State#state.timeout},
        {packet_spec, [?PACKET_SPEC]}
    ]};
init(server, Opts) ->
    lager:debug("init ping server with opts ~p", [Opts]),
    State = mk_state(Opts),
    {ok, State, [
        {active, once},
        {packet_spec, [?PACKET_SPEC]}
    ]}.

handle_packet(server, _, Packet, State = #state{}) ->
    %% Respond to inbound ping by echoing it back
    lager:debug("received packet and echoing back ~p", [Packet]),
    {noreply, State, [
        {active, once},
        {send, encode_ping(Packet)}
    ]};
handle_packet(client, _, Packet, State = #state{ping = Ping}) when Ping /= Packet ->
    %% After a previous timeout we could receive a very late pong reply. Ignore
    %% it for now since we're presumably either awaiting the next one, or in an
    %% idle interval wait.
    lager:info("Unrecognized ping response, ignoring"),
    {noreply, State, [
        {active, once}
    ]};
handle_packet(client, _, Packet, State = #state{ping = Ping}) when Ping == Packet ->
    %% Received a pong, Set the interval timer for when to send next.
    {noreply, State#state{ping = <<>>}, [
        {active, once},
        {timer, ping_interval, State#state.interval},
        {timer_cancel, {ping_timeout, Ping}}
    ]}.

handle_info(_Kind, {timeout, {ping_timeout, TimeoutPing}}, State = #state{ping = Ping}) when
    Ping /= TimeoutPing
->
    %% timeout received for a ping that is no longer valid, ignore
    {noreply, State, [
        {active, once}
    ]};
handle_info(_Kind, {timeout, {ping_timeout, TimeoutPing}}, State = #state{ping = Ping}) when
    Ping == TimeoutPing
->
    Failures = State#state.failures,
    case Failures > State#state.max_failures of
        true ->
            %% Maximum failures exceeded, stop this stream
            %% TODO: Make this close the underlying session if configured to do so?
            {stop, {error, ping_timeout}, State};
        false ->
            {noreply, State#state{failures = Failures + 1, ping = <<>>}, [
                {active, once},
                {timeout, ping_interval, State#state.interval}
            ]}
    end;
handle_info(_Kind, {timeout, ping_interval}, State = #state{ping = <<>>}) ->
    Ping = mk_ping(),
    {noreply, State#state{ping = Ping}, [
        {active, once},
        {send, encode_ping(Ping)},
        {timeout, {ping_timeout, Ping}}
    ]};
handle_info(Kind, Msg, State = #state{}) ->
    lager:warning("Unhandled ~p info ~p", [Kind, Msg]),
    {noreply, State}.

%%
%% Internal
%%

mk_ping() ->
    crypto:strong_rand_bytes(?PING_SIZE).

encode_ping(PingData) ->
    libp2p_packet:encode_packet([?PACKET_SPEC], [0], PingData).

mk_state(Opts) ->
    #state{
        timeout = timer:seconds(maps:get(timeout, Opts, ?DEFAULT_TIMEOUT_SECS)),
        interval = timer:seconds(maps:get(interval, Opts, ?DEFAULT_INTERVAL_SECS)),
        max_failures = timer:seconds(maps:get(max_failures, Opts, ?DEFAULT_MAX_FAILURES))
    }.
