-module(libp2p_stream_plaintext).

-behavior(libp2p_stream).

%% API
-export([handler/1]).
%% libp2p_stream
-export([
    init/2,
    handle_packet/4,
    protocol_id/0
]).

-include("pb/libp2p_plaintext_pb.hrl").

-record(state, {
    mod :: atom(),
    mod_opts :: map()
}).

%%
%% API
%%

handler(Opts) ->
    {protocol_id(), {?MODULE, Opts}}.

protocol_id() ->
    <<"/plaintext/2.0.0">>.

init(Kind, Opts = #{handler_fn := HandlerFun}) ->
    init(Kind, maps:remove(handler_fn, Opts#{handlers => HandlerFun()}));
init(Kind, Opts = #{handlers := Handlers}) ->
    ModOpts = maps:get(mod_opts, Opts, #{}),
    NewOpts = Opts#{
        mod => libp2p_stream_multistream,
        mod_opts => maps:merge(ModOpts, #{handlers => Handlers})
    },
    init(Kind, maps:remove(handlers, NewOpts));
init(Kind, #{mod := Mod, mod_opts := ModOpts, public_key := PubKey}) ->
    libp2p_stream_md:update({stack, {Mod, Kind}}),
    Exchange = #libp2p_plaintext_exchange_pb{
        id = libp2p_peer_id:to_bytes(libp2p_peer_id:from_public_key(PubKey)),
        pubkey = libp2p_key:to_proto(PubKey)
    },
    {ok, #state{mod = Mod, mod_opts = ModOpts}, [
        {active, once},
        {send, encode_exchange(Exchange)},
        {packet_spec, [varint]}
    ]}.

handle_packet(_, _, Packet, State = #state{}) ->
    Msg = libp2p_plaintext_pb:decode_msg(Packet, libp2p_plaintext_exchange_pb),
    #libp2p_plaintext_exchange_pb{id = OtherIdBytes, pubkey = OtherPubKeyProto} = Msg,
    OtherPeerId = libp2p_peer_id:from_public_key(libp2p_key:from_proto(OtherPubKeyProto)),
    case OtherIdBytes == libp2p_peer_id:to_bytes(OtherPeerId) of
        true ->
            %% TODO: MAYBE: client only: validate dialed server id against
            %% OtherId(?). The issue is that the dialed server id may have been
            %% dialed with it's ip multiaddr instead of the id
            {noreply, State, [{swap, State#state.mod, State#state.mod_opts}]};
        false ->
            {stop, {error, invalid_peer_exchange}, State}
    end.

encode_exchange(Exchange) ->
    Bin = libp2p_plaintext_pb:encode_msg(Exchange),
    libp2p_packet:encode_packet([varint], [byte_size(Bin)], Bin).
