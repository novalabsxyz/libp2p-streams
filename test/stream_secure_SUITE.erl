-module(stream_secure_SUITE).


-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
     dial_test
    ].

-define(TEST_PROTOCOL, <<"/test_secore/1.0.0/">>).

init_per_testcase(_, Config) ->
    test_util:setup(),
    meck_stream(test_echo),

    ClientIdentOpts = #{ identify_keys => ClientIdentKeys=test_util:mk_identify_keys()},
    ClientOpts =  #{ handlers => [libp2p_stream_identify:handler(ClientIdentOpts)] },

    ServerIdentKeys=#{sig_fun := ServerSigFun} = test_util:mk_identify_keys(),
    ServerIdentOpts = #{ identify_keys => ServerIdentKeys},
    ServerSecureKeys = libp2p_stream_secure:mk_keypair(ServerSigFun),
    ServerOpts = #{ handlers => [
                                 libp2p_stream_identify:handler(ServerIdentOpts),
                                 { ?TEST_PROTOCOL,
                                   {libp2p_stream_secure, #{ identify_keys => ServerIdentKeys,
                                                             secure_keys => ServerSecureKeys,
                                                             mod => test_echo,
                                                             mod_opts => #{ handler => {self(), server}}
                                                           } }}

                                ]
                  },
    IdentConfig = [{identify_keys, {ClientIdentKeys, ServerIdentKeys}} | Config],
    test_util:setup_mplex_streams(ClientOpts, ServerOpts, test_util:setup_sock_pair(IdentConfig)).

end_per_testcase(_, Config) ->
    test_util:teardown_sock_pair(Config),
    meck_unload_stream(test_echo),
    ok.


dial_test(Config) ->
    {CPid, _} = ?config(stream_client_server, Config),
    {CIdentKeys=#{sig_fun := ClientSigFun}, #{pubkey_bin := SPubKeyBin}} = ?config(identify_keys, Config),

    SPeerAddress = libp2p_crypto:pubkey_bin_to_p2p(SPubKeyBin),
    SecureOpts = #{ secure_keys => libp2p_stream_secure:mk_keypair(ClientSigFun),
                    identify_keys => CIdentKeys,
                    peer_address => SPeerAddress,
                    handlers => [{?TEST_PROTOCOL, {test_echo, #{handler => {self(), client}}}}]},

    libp2p_stream_secure:dial(CPid, SecureOpts),

    receive
        {test_echo, client, CStreamPid} -> ok
    after 5000 ->
            ct:fail(timeout_dial_test),
            CStreamPid = undefined
    end,

    ?assertEqual({ok, <<"hello world">>},
                 libp2p_stream_transport:command(CStreamPid, {send, <<"hello world">>})),

    ?assertEqual(SPubKeyBin,
                 libp2p_identify:pubkey_bin(libp2p_stream_transport:command(CStreamPid, get_identify))),

    SecureStack = [{libp2p_stream_secure, client}, {test_echo, client}],
    ?assert(lists:suffix(SecureStack, libp2p_stream_transport:command(CStreamPid, get_stack))),

    ok.


%%
%% Utilities
%%

encode_packet(Data) ->
    DataSize = byte_size(Data),
    libp2p_packet:encode_packet([u8], [DataSize], Data).


meck_stream(Name) ->
    meck:new(Name, [non_strict]),
    meck:expect(Name, init,
                fun(_, Opts=#{ handler := {HandlerPid, HandlerData} }) ->
                        HandlerPid ! {Name, HandlerData, self()},
                        {ok, Opts, [{packet_spec, [u8]},
                                    {active, once}
                                   ]}
                end),
    meck:expect(Name, handle_command,
                fun(_, {send, Data}, From, State) ->
                        {noreply, State#{sender => From},
                         [{send, encode_packet(Data)},
                          {timer, send_timeout, 5000}]
                        };
                   (_, get_identify, _From, State) ->
                        {reply, libp2p_stream_md:get(identify), State};
                   (_, get_stack, _From, State) ->
                        {reply, libp2p_stream_md:get(stack), State}
                end),
    meck:expect(Name, handle_packet,
               fun(_, _, Data, State) ->
                       case maps:take(sender, State) of
                           error ->
                               Packet = encode_packet(Data),
                               {noreply, State, [{send, Packet}]};
                           {From, NewState} ->
                               {noreply, NewState,
                                [{reply, From, {ok, Data}},
                                 {cancel_timer, send_timeout}]}
                       end
               end),
    meck:expect(Name, handle_info,
                fun(_, {timeout, send_timeout}, State) ->
                        case maps:take(sender, State) of
                            error ->
                                {noreply, State};
                            {From, NewState} ->
                                {noreply, NewState, [{reply, From, {error, send_timeout}}]}
                        end
                end),
    ok.


meck_unload_stream(Name) ->
    meck:unload(Name).
