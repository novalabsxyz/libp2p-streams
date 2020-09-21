-module(stream_plaintext_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
        dial_test
    ].

init_per_testcase(_, Config) ->
    test_util:setup(),
    init_test_streams(test_util:setup_sock_pair(Config)).

init_test_streams(Config) ->
    {CSock, SSock} = ?config(client_server, Config),

    ServerKeypair = libp2p_keypair:new(ed25519),
    {ok, SPid} = libp2p_stream_tcp:start_link(server, #{
        socket => SSock,
        handlers => [
            libp2p_stream_plaintext:handler(#{
                public_key => libp2p_keypair:public_key(ServerKeypair),
                handlers => [
                    test_stream_echo:handler(<<"echo_server">>, #{
                        name => echo_server,
                        handler => {self(), server}
                    })
                ]
            })
        ]
    }),
    gen_tcp:controlling_process(SSock, SPid),

    ClientKeypair = libp2p_keypair:new(ed25519),
    {ok, CPid} = libp2p_stream_tcp:start_link(client, #{
        socket => CSock,
        handlers => [
            libp2p_stream_plaintext:handler(#{
                public_key => libp2p_keypair:public_key(ClientKeypair),
                handlers => [
                    test_stream_echo:handler(<<"echo_server">>, #{
                        name => echo_client,
                        handler => {self(), client}
                    })
                ]
            })
        ]
    }),
    gen_tcp:controlling_process(CSock, CPid),

    [{stream_client_server, {CPid, SPid}} | Config].

end_per_testcase(_, Config) ->
    test_util:teardown_sock_pair(Config),
    ok.

dial_test(_Config) ->
    receive
        {echo_client, client, CStreamPid} -> ok
    after 5000 ->
        ct:fail(timeout_dial_test),
        CStreamPid = undefined
    end,

    ?assertEqual(
        {ok, <<"hello world">>},
        libp2p_stream_transport:command(CStreamPid, {send, <<"hello world">>})
    ),

    ok.
