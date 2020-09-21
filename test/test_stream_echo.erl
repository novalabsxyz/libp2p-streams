-module(test_stream_echo).

-export([handler/2, init/2, handle_command/4, handle_packet/4, handle_info/3]).

handler(ProtocolId, Opts) ->
    {ProtocolId, {?MODULE, Opts}}.

init(_, Opts = #{name := Name, handler := {HandlerPid, HandlerData}}) ->
    HandlerPid ! {Name, HandlerData, self()},
    {ok, Opts, [
        {packet_spec, [u8]},
        {active, once}
    ]}.

handle_command(_, {send, Data}, From, State) ->
    {noreply, State#{sender => From}, [
        {send, encode_packet(Data)},
        {timer, send_timeout, 5000}
    ]};
handle_command(_, get_identify, _From, State) ->
    {reply, libp2p_stream_md:get(identify), State};
handle_command(_, get_stack, _From, State) ->
    {reply, libp2p_stream_md:get(stack), State}.

handle_packet(_, _, Data, State) ->
    case maps:take(sender, State) of
        error ->
            Packet = encode_packet(Data),
            {noreply, State, [{send, Packet}]};
        {From, NewState} ->
            {noreply, NewState, [
                {reply, From, {ok, Data}},
                {cancel_timer, send_timeout}
            ]}
    end.

handle_info(_, {timeout, send_timeout}, State) ->
    case maps:take(sender, State) of
        error ->
            {noreply, State};
        {From, NewState} ->
            {noreply, NewState, [{reply, From, {error, send_timeout}}]}
    end.

encode_packet(Data) ->
    DataSize = byte_size(Data),
    libp2p_packet:encode_packet([u8], [DataSize], Data).
