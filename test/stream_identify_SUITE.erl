-module(stream_identify_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
     dial_test
    ].

init_per_testcase(_, Config) ->
    test_util:setup(),
    init_test_streams(test_util:setup_sock_pair(Config)).

end_per_testcase(_, Config) ->
    test_util:teardown_sock_pair(Config).


mk_ident_keys() ->
    #{public := PubKey, secret := PrivKey } = libp2p_crypto:generate_keys(ecc_compact),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    PubKeyBin = libp2p_crypto:pubkey_to_bin(PubKey),
    #{pubkey_bin => PubKeyBin, sig_fun => SigFun }.

init_test_streams(Config) ->
    {CSock, SSock} = ?config(client_server, Config),

    %% Server muxer
    ServerOpts = #{ handlers => [{ libp2p_stream_identify:protocol_id(),
                                   {libp2p_stream_identify, mk_ident_keys() }
                                 }]},
    {ok, SPid} = libp2p_stream_tcp:start_link(server, #{socket => SSock,
                                                        mod => libp2p_stream_mplex,
                                                        mod_opts => ServerOpts
                                                    }),
    gen_tcp:controlling_process(SSock, SPid),

    %% Client muxer
    {ok, CPid} = libp2p_stream_tcp:start_link(client, #{socket => CSock,
                                                        mod => libp2p_stream_mplex
                                                       }),
    gen_tcp:controlling_process(CSock, CPid),
    [{stream_client_server, {CPid, SPid}} | Config].



dial_test(Config) ->
    {CPid, _} = ?config(stream_client_server, Config),

    IdentOpts = mk_ident_keys(),
    libp2p_stream_identify:dial(CPid, IdentOpts),

    %% Wait for the identify to make it to the muxer
    ok = test_util:wait_until(fun() ->
                                      stream_identify(CPid) /= undefined
                              end),

    %% Check that the observe address of the client as returned by the
    %% server matches our local address in addr_info
    Identify = stream_identify(CPid),
    {ok, {LocalAddr, _}} = libp2p_stream_transport:command(CPid, stream_addr_info),
    ?assertEqual(LocalAddr, libp2p_identify:observed_addr(Identify)),

    ok.


%%
%% Utilities
%%

stream_identify(Pid) ->
    {dictionary, PDict} = erlang:process_info(Pid, dictionary),
    case lists:keyfind(stream_identify, 1, PDict) of
        false -> undefined;
        {stream_identify, Info} -> Info
    end.

stream_stack(Pid) ->
    {dictionary, PDict} = erlang:process_info(Pid, dictionary),
    {stream_stack, Stack} = lists:keyfind(stream_stack, 1, PDict),
    Stack.

meck_stream(Name) ->
    meck:new(Name, [non_strict]),
    meck:expect(Name, init,
                   fun(_, Opts) ->
                           {ok, Opts, []}
                   end),
    meck:expect(Name, handle_command,
                fun(_Kind, stream_identify, _From, State) ->
                        {reply, {ok, libp2p_stream_transport:get(stream_identify)}, State};
                   (_Kind, stream_addr_info, _From, State) ->
                        {reply, {ok, libp2p_stream_transport:get(stream_addr_info)}, State}
                end),
    ok.


meck_unload_stream(Name) ->
    meck:unload(Name).
