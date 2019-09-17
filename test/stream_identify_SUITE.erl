-module(stream_identify_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
     dial_test
    ].

init_per_testcase(_, Config) ->
    test_util:setup(),
    ClientOpts = #{},
    ServerIdentOpts = #{identify_keys => test_util:mk_identify_keys()},
    ServerOpts = #{ handlers => [libp2p_stream_identify:handler(ServerIdentOpts)] },
    test_util:setup_mplex_streams(ClientOpts, ServerOpts, test_util:setup_sock_pair(Config)).

end_per_testcase(_, Config) ->
    test_util:teardown_sock_pair(Config).



dial_test(Config) ->
    {CPid, _} = ?config(stream_client_server, Config),

    IdentOpts = #{identify_keys => test_util:mk_identify_keys(),
                  identify_handler => {self(), test_ident}},
    libp2p_stream_muxer:identify(CPid, IdentOpts),
    receive
        {handle_identify, test_ident, {ok, _}} -> ok;
        {handle_identify, test_ident, {error, Other}} -> ct:fail(Other)
    after 5000 ->
            ct:fail(timeout_dial_test)
    end,

    %% Check that the observe address of the client as returned by the
    %% server matches our local address in addr_info
    Identify = test_util:get_md(identify, CPid),
    {ok, {LocalAddr, _}} = libp2p_stream_transport:command(CPid, stream_addr_info),
    ?assertEqual(LocalAddr, libp2p_identify:observed_addr(Identify)),

    ok.


%%
%% Utilities
%%

meck_stream(Name) ->
    meck:new(Name, [non_strict]),
    meck:expect(Name, init,
                   fun(_, Opts) ->
                           {ok, Opts, []}
                   end),
    meck:expect(Name, handle_command,
                fun(_Kind, stream_identify, _From, State) ->
                        {reply, {ok, libp2p_stream_md:get(identify)}, State};
                   (_Kind, stream_addr_info, _From, State) ->
                        {reply, {ok, libp2p_stream_md:get(addr_info)}, State}
                end),
    ok.


meck_unload_stream(Name) ->
    meck:unload(Name).
